"""十条契约测试：每条对应 README 列出的一个缺陷。"""

import pytest

from mfa import enroll


def _store(max_devices=3, pending_ttl=300):
    return {
        "policy": {
            "max_devices": max_devices,
            "backup_codes": True,
            "pending_ttl": pending_ttl,
        },
        "pending": {},
        "devices": {},
        "sessions": {},
        "backup_redemptions": [],
        "entropy": b"unit-contract-server-entropy",
    }


def _user(user_id="u1", device_id="phone-a"):
    return {"id": user_id, "device_id": device_id, "backup_codes": []}


def _device(secret):
    return {"active": True, "secret": secret, "bound_at": 500}


def test_defect_01_begin_records_expiry_with_zero_tolerance():
    """缺陷 1：待确认记录必须带 expires_at，过期边界没有宽限。"""
    store = _store(pending_ttl=300)
    user = _user()

    pending = enroll.begin(store, user, 1000)

    assert pending["user_id"] == "u1"
    assert pending["device_id"] == "phone-a"
    assert pending["issued_at"] == 1000
    assert pending["expires_at"] == 1300
    assert store["pending"]["u1"] == pending


def test_defect_02_confirm_rejects_device_mismatch_and_duplicate_binding():
    """缺陷 2：确认必须比对设备标识，且同一设备不能重复绑定。"""
    store = _store()
    owner = _user("u1", "phone-a")
    pending = enroll.begin(store, owner, 1000)

    attacker = _user("u1", "phone-b")
    with pytest.raises(ValueError):
        enroll.confirm(store, attacker, pending["code"], 1001)

    confirmed = enroll.confirm(store, owner, pending["code"], 1002)
    assert confirmed["device_id"] == "phone-a"

    duplicate = _user("u2", "phone-a")
    with pytest.raises(ValueError):
        enroll.begin(store, duplicate, 1003)


def test_defect_03_device_limit_reaches_zero_at_capacity():
    """缺陷 3：活跃设备数达到上限时返回 0，不能多放行一台。"""
    store = _store(max_devices=2)
    user = _user()
    store["devices"] = {
        "u1": {
            "phone-a": _device(b"secret-a"),
            "tablet": _device(b"secret-b"),
        }
    }

    assert enroll.device_limit(store, user) == 0

    store["devices"]["u1"].pop("tablet")
    assert enroll.device_limit(store, user) == 1

    store["devices"]["u1"]["laptop"] = _device(b"secret-c")
    assert enroll.device_limit(store, user) == 0


def test_defect_04_revoke_clears_device_secret():
    """缺陷 4：撤销必须清除密钥，旧设备不能继续通过校验。"""
    store = _store()
    user = _user()
    store["devices"] = {
        "u1": {
            "phone-a": _device(b"legacy-secret"),
            "tablet": _device(b"tablet-secret"),
        }
    }

    result = enroll.revoke_device(store, user, "phone-a")

    revoked = store["devices"]["u1"]["phone-a"]
    assert result["revoked"] is True
    assert result["secret_cleared"] is True
    assert revoked["active"] is False
    assert revoked["secret"] is None
    assert "legacy-secret" not in repr(store)
    assert store["devices"]["u1"]["tablet"]["active"] is True
    assert store["devices"]["u1"]["tablet"]["secret"] == b"tablet-secret"


def test_defect_05_backup_codes_are_stored_as_hashes_only():
    """缺陷 5：备用码只能存哈希，明文不得落入用户记录。"""
    user = _user()
    codes = enroll.backup_codes(user, b"entropy-for-unit-5", 6)
    records = user["backup_codes"]

    assert len(codes) == 6
    assert len(records) == 6
    assert len(set(codes)) == 6
    assert all(len(code) == 10 for code in codes)
    assert all(code.isalnum() and code.upper() == code for code in codes)
    assert all(record["used"] is False for record in records)
    assert all(
        len(record["code_hash"]) == 64
        and all(char in "0123456789abcdef" for char in record["code_hash"])
        for record in records
    )

    for code in codes:
        for record in records:
            values = list(record.values())
            assert code not in values
            assert code.encode("utf-8") not in values


def test_defect_06_backup_code_can_be_used_only_once():
    """缺陷 6：备用码消费必须记录，第二次使用同一码失败。"""
    user = _user()
    store = _store()
    codes = enroll.backup_codes(user, b"entropy-for-unit-6", 2)

    assert enroll.use_backup_code(store, user, codes[0]) is True
    assert user["backup_codes"][0]["used"] is True
    assert len(store["backup_redemptions"]) == 1

    assert enroll.use_backup_code(store, user, codes[0]) is False
    assert len(store["backup_redemptions"]) == 1

    assert enroll.use_backup_code(store, user, codes[1]) is True


def test_defect_07_backup_codes_are_unique_and_exact_count():
    """缺陷 7：生成数量必须等于 count，且每个码互不重复。"""
    user = _user()
    count = 32

    codes = enroll.backup_codes(user, b"entropy-for-unit-7", count)

    assert len(codes) == count
    assert len(set(codes)) == count
    assert len(user["backup_codes"]) == count
    assert len({record["code_hash"] for record in user["backup_codes"]}) == count


def test_defect_08_validate_policy_checks_device_limit():
    """缺陷 8：策略校验必须把设备数上限当成必填安全项。"""
    valid = {"max_devices": 2, "backup_codes": True, "pending_ttl": 300}
    missing = {"backup_codes": True, "pending_ttl": 300}
    zero = {"max_devices": 0, "backup_codes": True, "pending_ttl": 300}

    assert enroll.validate_policy(valid) == []
    assert enroll.validate_policy(missing) == ["device_limit_missing"]
    assert enroll.validate_policy(zero) == ["device_limit_missing"]


def test_defect_09_batch_keeps_pending_records_separate():
    """缺陷 9：批量处理按用户隔离待确认记录，后一个用户不命中前一个。"""
    store = _store(max_devices=3)
    first = _user("u1", "phone-a")
    second = _user("u2", "phone-b")
    events = [
        {"id": "first", "store": store, "user": first},
        {"id": "second", "store": store, "user": second},
    ]

    result = enroll.enroll_batch(events, store["policy"], 2000)

    assert set(result) == {"first", "second"}
    assert result["first"]["user_id"] == "u1"
    assert result["first"]["device_id"] == "phone-a"
    assert result["second"]["user_id"] == "u2"
    assert result["second"]["device_id"] == "phone-b"
    assert result["first"]["code"] != result["second"]["code"]
    assert set(store["pending"]) == {"u1", "u2"}
    assert store["pending"]["u1"]["device_id"] == "phone-a"
    assert store["pending"]["u2"]["device_id"] == "phone-b"


def test_defect_10_revoke_notifies_session_layer():
    """缺陷 10：撤销必须通知会话层，旧会话不能继续有效。"""
    store = _store()
    user = _user()
    store["devices"] = {
        "u1": {
            "phone-a": _device(b"secret-a"),
            "tablet": _device(b"secret-b"),
        }
    }
    store["sessions"] = {
        "session-a1": {"user_id": "u1", "device_id": "phone-a", "active": True},
        "session-a2": {"user_id": "u1", "device_id": "phone-a", "active": True},
        "session-b1": {"user_id": "u1", "device_id": "tablet", "active": True},
    }

    result = enroll.revoke_device(store, user, "phone-a")

    assert result["sessions_invalidated"] == 2
    assert result["session_layer_notified"] is True
    assert store["sessions"]["session-a1"]["active"] is False
    assert store["sessions"]["session-a2"]["active"] is False
    assert store["sessions"]["session-a1"]["revoked"] is True
    assert store["sessions"]["session-a2"]["revoked"] is True
    assert store["sessions"]["session-b1"]["active"] is True
