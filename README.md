用户换手机要重新绑定二次验证，结果旧设备一直没被踢下线：绑定记录不写入过期时间，未确认记录永久有效；确认时不比对设备标识，任意设备都能完成确认；设备上限判断用大于而不是大于等于，实际多绑一台；撤销设备只标记失效而不清除密钥，旧密钥仍能通过校验；备用码明文存储，一旦泄露即可直接使用；备用码消费后不记录，同一个码可以重复使用；备用码生成存在重复项，导致数量不足；策略校验不检查设备数上限；批量处理复用待确认记录，后一个用户会命中前一个用户；撤销设备后不通知会话层，旧会话仍然有效。mfa/enroll.py 是核心，tests/unit/test_enroll.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式与初始状态

在仓库根目录执行：

    pytest tests -q

初始状态必须恰好输出 15 failed，不能出现 collection error、import error、syntax error 或 test error。15 个失败都应来自 mfa/enroll.py 的 NotImplementedError；如果失败数不是 15 或出现 error，说明环境或测试文件已损坏，不应继续。实现完成后应为 15 passed。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 契约与约束

- mfa/enroll.py 恰好提供 8 个公开函数，当前全部抛出 NotImplementedError；函数 docstring 是修复契约的一部分。
- 只使用标准库 hmac、hashlib、base64、time 与 pytest；离线运行，不联网，不安装额外依赖。
- 不使用 random 或隐式的系统时钟。备用码熵源 entropy 和当前时间 now 均由调用方显式传入。
- 时间过期容差为 0：now 大于等于 expires_at 即失效，不保留宽限。
- 绑定唯一：同一 device_id 不得同时绑定给两个用户，也不得重复绑定；备用码生成数量必须精确等于 count，且每个码只能消费一次。
- 只允许修改 mfa/enroll.py，用测试结果验证修复。

## tests 不可修改

tests/unit/test_enroll.py 与 tests/behaviour/test_enroll_edge.py 是固定的验收契约，不得修改、删除、跳过、xfail、参数化或改写断言。不得通过改动测试来改变初始的 15 failed。

## 测试拆分布局

这是测试拆分布局，不使用单文件平铺：

- tests/unit/test_enroll.py：10 条契约测试，逐条对应题面中的 10 个缺陷。
- tests/behaviour/test_enroll_edge.py：5 条边界测试，覆盖正常绑定、未确认记录过期被拒、超过设备上限被拒、撤销后校验失败、两批独立处理与单独处理相同。
- conftest.py：把仓库根加入 sys.path，两个测试目录都通过它导入 mfa 包。

unit 与 behaviour 两个目录合计 15 条测试，统一用 pytest tests -q 收集，初始恰好 15 failed。
