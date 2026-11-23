"""五条边界测试：正常绑定、过期、上限、撤销校验与批次一致性。"""

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
        "entropy": b"behaviour-edge-server-entropy",
    }


def _user(user_id="u1", device_id="phone-a"):
    return {"id": user_id, "device_id": device_id, "backup_codes": []}


def _device(secret):
    return {"active": True, "secret": secret, "bound_at": 500}


def _can_validate(record):
    return bool(record and record.get("active") is True and record.get("secret"))


def test_normal_enrollment_succeeds():
    """合法确认应写入启用的设备记录并清理待确认记录。"""
    store = _store(max_devices=2)
    user = _user()

    pending = enroll.begin(store, user, 1000)
    confirmed = enroll.confirm(store, user, pending["code"], 1010)

    record = store["devices"]["u1"]["phone-a"]
    assert confirmed["active"] is True
    assert confirmed["device_id"] == "phone-a"
    assert confirmed["bound_at"] == 1010
    assert record["active"] is True
    assert len(record["secret"]) == 64
    assert user["id"] not in store["pending"]


def test_expired_pending_binding_is_rejected():
    """now 恰好到达 expires_at 时必须拒绝，时间容差为 0。"""
    store = _store(pending_ttl=300)
    user = _user()
    pending = enroll.begin(store, user, 1000)

    with pytest.raises(ValueError):
        enroll.confirm(store, user, pending["code"], 1300)

    assert store["devices"].get("u1", {}) == {}


def test_binding_above_device_limit_is_rejected():
    """已有设备数等于上限时，第三台设备必须被拒绝。"""
    store = _store(max_devices=2)
    store["devices"] = {
        "u1": {
            "phone-a": _device(b"secret-a"),
            "tablet": _device(b"secret-b"),
        }
    }
    third = _user("u1", "phone-c")

    with pytest.raises(ValueError):
        pending = enroll.begin(store, third, 3000)
        enroll.confirm(store, third, pending["code"], 3001)

    assert "phone-c" not in store["devices"]["u1"]


def test_revoked_device_fails_validation():
    """撤销后设备失去有效密钥，设备校验必须失败。"""
    store = _store()
    user = _user()
    store["devices"] = {"u1": {"phone-a": _device(b"old-device-secret")}}
    store["sessions"] = {
        "session-old": {"user_id": "u1", "device_id": "phone-a", "active": True}
    }

    enroll.revoke_device(store, user, "phone-a")

    record = store["devices"]["u1"]["phone-a"]
    assert _can_validate(record) is False
    assert record["secret"] is None
    assert store["sessions"]["session-old"]["active"] is False


def test_two_batches_match_individual_processing():
    """两个独立批次的结果分别应与各自单独处理一致。"""
    policy = _store()["policy"]
    first = _user("u1", "phone-a")
    second = _user("u2", "phone-b")

    first_store = _store()
    first_batch = enroll.enroll_batch(
        [{"id": "first", "store": first_store, "user": first}],
        policy,
        4000,
    )
    second_store = _store()
    second_batch = enroll.enroll_batch(
        [{"id": "second", "store": second_store, "user": second}],
        policy,
        4000,
    )

    solo_first = enroll.begin(_store(), first, 4000)
    solo_second = enroll.begin(_store(), second, 4000)

    assert first_batch == {"first": solo_first}
    assert second_batch == {"second": solo_second}
