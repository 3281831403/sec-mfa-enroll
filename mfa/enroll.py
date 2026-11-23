"""二次验证设备绑定、撤销与备用码的安全契约桩。

本模块只有八个公开函数，全部抛出 NotImplementedError，等待按题面顺序修复。
调用方持有可变的 store 字典，结构约定如下：

- store["policy"]：绑定策略，含 max_devices、backup_codes、pending_ttl；
- store["pending"]：按用户 id 保存待确认记录；
- store["devices"]：按用户 id 保存设备记录，设备记录再按 device_id 索引；
- store["sessions"]：按会话 id 保存会话记录，记录含 user_id、device_id、active；
- store["backup_redemptions"]：备用码消费审计列表；
- store["entropy"]：调用方显式提供的服务端熵字节串。

user 是至少含 id、device_id、backup_codes 三个字段的可变字典。现在时间 now
一律由调用方显式传入，模块不读取系统时钟，也不使用随机数。所有时间边界容差
为 0：now 达到 expires_at 即视为过期，不保留任何宽限。绑定唯一：同一
device_id 不得同时绑定到两个用户，也不得重复写入。备用码数量必须与 count
完全一致，且每个备用码只能消费一次。
"""

import base64
import hashlib
import hmac

_STORE_MISSING = object()


def _is_positive_int(value) -> bool:
    """正整数判定：布尔值不能冒充整数。"""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _entropy(store):
    """取出调用方显式提供的熵源，缺失时视为配置错误。"""
    entropy = store.get("entropy")
    if not isinstance(entropy, (bytes, bytearray, str)):
        raise ValueError("store must provide bytes entropy")
    return entropy


def _key(entropy) -> bytes:
    if isinstance(entropy, str):
        return entropy.encode("utf-8")
    return bytes(entropy)


def _digest(entropy, *parts) -> bytes:
    """对 entropy 与显式上下文做 HMAC-SHA256，不读取时钟或随机源。"""
    message = b"\x00".join(
        part if isinstance(part, (bytes, bytearray)) else str(part).encode("utf-8")
        for part in parts
    )
    return hmac.new(_key(entropy), message, hashlib.sha256).digest()


def _hex_digest(entropy, *parts) -> str:
    return _digest(entropy, *parts).hex()


def _devices_of(store, user_id):
    """只读地取某个用户的设备表，不因查询而创建空表。"""
    devices = store.get("devices")
    if not isinstance(devices, dict):
        return {}
    records = devices.get(user_id)
    return records if isinstance(records, dict) else {}


def _active_device_exists(store, device_id) -> bool:
    """device_id 是否已作为启用设备绑定到任何用户。"""
    devices = store.get("devices")
    if not isinstance(devices, dict):
        return False
    for records in devices.values():
        if not isinstance(records, dict):
            continue
        record = records.get(device_id)
        if record is not None and record.get("active") is True:
            return True
    return False


def begin(store, user, now) -> dict:
    """开始绑定，生成带过期时间的待确认记录。

    在 store["pending"][user["id"]] 写入一条记录并返回该记录。记录至少包含
    user_id、device_id、code、issued_at、expires_at。expires_at 必须等于
    issued_at 加 store["policy"]["pending_ttl"]，不得省略；时间容差为 0，确认时
    now 大于等于 expires_at 即拒绝。确认码由 store["entropy"]、用户 id、设备
    id 和 now 经 HMAC-SHA256 派生，结果稳定且不读取系统时钟。

    绑定唯一：如果同一 device_id 已绑定到任何用户，或者当前用户已有未过期的
    待确认记录，必须抛出 ValueError。可用设备数为 0 时也不得创建记录。成功时
    返回刚写入的待确认记录，其中 code 是用户完成确认所需的明文挑战码。
    """
    user_id = user["id"]
    device_id = user["device_id"]
    policy = store.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a dict")
    pending_ttl = policy.get("pending_ttl")
    if not _is_positive_int(pending_ttl):
        raise ValueError("pending_ttl must be a positive integer")

    # 缺陷 2：同一设备不得同时绑定到任何用户。
    if _active_device_exists(store, device_id):
        raise ValueError("device is already bound")

    pending = store.get("pending")
    if isinstance(pending, dict):
        existing = pending.get(user_id)
        # 缺陷 1：只有真正过期的旧记录才允许被覆盖，且 now == expires_at 已过期。
        if existing is not None and now < existing.get("expires_at", 0):
            raise ValueError("user already has an unexpired pending enrollment")

    if device_limit(store, user) <= 0:
        raise ValueError("device limit reached")

    code = _hex_digest(_entropy(store), "enroll-challenge", user_id, device_id, now)
    record = {
        "user_id": user_id,
        "device_id": device_id,
        "code": code,
        "issued_at": now,
        "expires_at": now + pending_ttl,
    }
    if not isinstance(pending, dict):
        pending = store["pending"] = {}
    pending[user_id] = record
    return record


def confirm(store, user, code, now) -> dict:
    """确认绑定，把设备标识唯一地写入设备表。

    必须依次检查：待确认记录存在；code 与记录中的挑战码用
    hmac.compare_digest 相等；user["device_id"] 与记录中的 device_id 完全一致；
    now 严格小于 expires_at。任一项不满足都抛出 ValueError，且不得写入设备。

    随后检查绑定唯一与设备上限：device_id 已绑定到任何用户时拒绝；调用
    device_limit 后可用数量必须大于 0。成功时向 store["devices"] 写入 active
    为 True 的设备记录，记录含 bound_at、secret、active、device_id；secret 是
    由 store["entropy"] 与用户、设备、时间派生的 64 位小写十六进制值。最后删除
    待确认记录，返回新设备记录。重复确认同一待确认记录必须失败。
    """
    user_id = user["id"]
    device_id = user["device_id"]
    pending_store = store.get("pending")
    pending = pending_store.get(user_id) if isinstance(pending_store, dict) else None
    if pending is None:
        raise ValueError("no pending enrollment")

    expected_code = pending.get("code")
    if (
        not isinstance(code, str)
        or not isinstance(expected_code, str)
        or not hmac.compare_digest(code, expected_code)
    ):
        raise ValueError("invalid confirmation code")

    # 缺陷 2：确认的设备必须与发起绑定的设备一致。
    if device_id != pending.get("device_id"):
        raise ValueError("confirmation device does not match enrollment")

    # 缺陷 1：now 达到 expires_at 即拒绝，没有宽限。
    if now >= pending.get("expires_at", 0):
        raise ValueError("pending enrollment expired")

    if _active_device_exists(store, device_id):
        raise ValueError("device is already bound")
    if device_limit(store, user) <= 0:
        raise ValueError("device limit reached")

    secret = _hex_digest(_entropy(store), "device-secret", user_id, device_id, now)
    record = {
        "device_id": device_id,
        "bound_at": now,
        "secret": secret,
        "active": True,
    }
    devices = store.get("devices")
    if not isinstance(devices, dict):
        devices = store["devices"] = {}
    devices.setdefault(user_id, {})[device_id] = record
    del pending_store[user_id]
    return record


def device_limit(store, user) -> int:
    """返回该用户还能新增的设备数量，边界容差为 0。

    只统计 store["devices"][user["id"]] 中 active 为 True 的记录。设策略
    max_devices 为 N、活跃设备数为 K：K 小于 N 时返回 N 减 K；K 大于等于 N 时
    返回 0，绝不返回负数。也就是说达到上限必须立即拒绝，不能因为使用大于而
    多放行一台。max_devices 必须是正整数，否则抛出 ValueError。
    """
    policy = store.get("policy")
    max_devices = policy.get("max_devices") if isinstance(policy, dict) else None
    if not _is_positive_int(max_devices):
        raise ValueError("max_devices must be a positive integer")

    active = sum(
        1
        for record in _devices_of(store, user["id"]).values()
        if isinstance(record, dict) and record.get("active") is True
    )
    # 缺陷 3：K >= N 即返回 0，不能多放行一台。
    if active >= max_devices:
        return 0
    return max_devices - active


def revoke_device(store, user, device_id) -> dict:
    """撤销单台设备，立即清除密钥并通知会话层。

    把 store["devices"][user["id"]][device_id] 改成 active 为 False、
    secret 为 None、revoked 为 True 的墓碑记录；必须真正删除或清空密钥，不能
    只改 active 而保留旧密钥。随后遍历 store["sessions"]，把 user_id 与
    device_id 都匹配且原先 active 为 True 的会话立即置为 active 为 False，并
    给会话记录写入 revoked 为 True。其他设备的会话保持不变。

    返回字典至少含 user_id、device_id、revoked、secret_cleared、
    sessions_invalidated、session_layer_notified。device_id 不存在或已经撤销
    时抛出 ValueError。
    """
    user_id = user["id"]
    record = _devices_of(store, user_id).get(device_id)
    if not isinstance(record, dict):
        raise ValueError("device not found")
    if record.get("revoked") is True:
        raise ValueError("device already revoked")

    # 缺陷 4：真正清空密钥，旧密钥不能再通过校验。
    record["active"] = False
    record["secret"] = None
    record["revoked"] = True

    invalidated = 0
    sessions = store.get("sessions")
    if isinstance(sessions, dict):
        for session in sessions.values():
            if not isinstance(session, dict):
                continue
            # 缺陷 10：撤销后立即通知会话层，把该设备的活动会话全部作废。
            if (
                session.get("user_id") == user_id
                and session.get("device_id") == device_id
                and session.get("active") is True
            ):
                session["active"] = False
                session["revoked"] = True
                invalidated += 1

    return {
        "user_id": user_id,
        "device_id": device_id,
        "revoked": True,
        "secret_cleared": True,
        "sessions_invalidated": invalidated,
        "session_layer_notified": True,
    }


def backup_codes(user, entropy, count) -> list:
    """生成恰好 count 个互不重复的一次性备用码，只存哈希。

    count 必须是正整数。返回 count 个长度为 10 的大写 Base32 字符码，码之间
    不得重复；user["backup_codes"] 必须被替换为同样数量的哈希记录，每条记录含
    salt、code_hash、used。code_hash 是
    sha256((salt + 明文码).encode("utf-8")).hexdigest()，为 64 位小写十六进制；
    salt 是 16 位小写十六进制字符串，由 entropy 与用户 id、序号经 HMAC-SHA256
    派生后截取。明文码只能出现在
    返回值中，绝不能写入 user，也不能以其他字段明文保存。

    生成过程只使用调用方传入的 entropy，不读取系统时钟、不使用随机源。数量、
    唯一性和哈希存储三项都必须精确满足。
    """
    if not _is_positive_int(count):
        raise ValueError("count must be a positive integer")

    user_id = user["id"]
    codes = []
    seen = set()
    counter = 0
    # 缺陷 7：碰撞时继续派生，直到恰好拿到 count 个互不重复的码。
    while len(codes) < count:
        candidate = base64.b32encode(
            _digest(entropy, "backup-code", user_id, counter)
        ).decode("ascii")[:10]
        counter += 1
        if candidate in seen:
            continue
        seen.add(candidate)
        codes.append(candidate)

    records = []
    for index, code in enumerate(codes):
        salt = _hex_digest(entropy, "backup-salt", user_id, index)[:16]
        # 缺陷 5：只保存哈希，明文码绝不落入 user 记录。
        code_hash = hashlib.sha256((salt + code).encode("utf-8")).hexdigest()
        records.append({"salt": salt, "code_hash": code_hash, "used": False})

    user["backup_codes"] = records
    return codes


def use_backup_code(store, user, code) -> bool:
    """消费一个备用码，成功消费后立即失效。

    遍历 user["backup_codes"] 中尚未消费的记录，按记录中的 salt 与传入明文码
    重算 SHA-256，使用 hmac.compare_digest 比较 code_hash。匹配时把该记录的
    used 改为 True，并向 store["backup_redemptions"] 追加一条含 user_id、
    code_hash 的消费审计，返回 True。

    已消费的记录不得再次匹配，同一个码第二次调用必须返回 False；未匹配返回
    False。消费记录必须落在 user 与 store 中，不能只放在模块级临时变量里。
    """
    if not isinstance(code, str):
        return False

    for record in user.get("backup_codes", []):
        if not isinstance(record, dict):
            continue
        # 缺陷 6：已消费的记录不得再次参与匹配。
        if record.get("used"):
            continue
        salt = record.get("salt", "")
        code_hash = record.get("code_hash", "")
        candidate = hashlib.sha256((salt + code).encode("utf-8")).hexdigest()
        if hmac.compare_digest(candidate, code_hash):
            record["used"] = True
            redemptions = store.get("backup_redemptions")
            if not isinstance(redemptions, list):
                redemptions = store["backup_redemptions"] = []
            redemptions.append({"user_id": user["id"], "code_hash": code_hash})
            return True
    return False


def validate_policy(policy) -> list[str]:
    """返回策略问题代码列表，合法策略返回空列表。

    固定按以下顺序检查并返回问题代码：

    - invalid_policy：policy 不是字典；
    - device_limit_missing：max_devices 缺失或不是正整数；
    - backup_codes_disabled：backup_codes 不严格等于 True；
    - pending_ttl_missing：pending_ttl 缺失或不是正整数。

    设备数上限必须被显式检查，不能只检查备用码与过期时间。全部合法时返回空
    列表。布尔值不能冒充整数上限。
    """
    if not isinstance(policy, dict):
        return ["invalid_policy"]

    problems = []
    # 缺陷 8：设备数上限是必填安全项，必须显式校验。
    if not _is_positive_int(policy.get("max_devices")):
        problems.append("device_limit_missing")
    if policy.get("backup_codes") is not True:
        problems.append("backup_codes_disabled")
    if not _is_positive_int(policy.get("pending_ttl")):
        problems.append("pending_ttl_missing")
    return problems


def enroll_batch(events, policy, now) -> dict:
    """批量开始绑定，各事件完全独立。

    events 是字典序列，每个事件含 id、store、user。先验证 policy，存在问题时
    抛出 ValueError。然后按事件逐个调用 begin，返回 id 到结果的字典：成功项是
    begin 返回的待确认记录，失败项是该事件捕获到的 ValueError 实例。一个事件
    失败不得影响其他事件，也不得把前一个用户的待确认记录复用给后一个用户。

    每个事件必须使用自己的 store 与 user；即使多个事件共享同一个 store，也必须
    按 user["id"] 分别写入待确认记录，不能共用一个局部 pending 变量。
    """
    problems = validate_policy(policy)
    if problems:
        raise ValueError("invalid policy: " + ", ".join(problems))

    results = {}
    for event in events:
        event_id = event["id"]
        try:
            # 缺陷 9：每个事件使用自己的 store 与 user，按用户 id 分别落库。
            results[event_id] = begin(event["store"], event["user"], now)
        except ValueError as exc:
            results[event_id] = exc
    return results
