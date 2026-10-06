# 施工版便携派生变更清单

日期：2026-10-04；派生版本：`CK-FINAL-20260928-01-portable-20261004`。

可信来源为 `m2-construction-final-r1.zip`，原 SHA-256：`e34f84ecca424115c1bcdb2df37e63e0c0c2d029c52662d1cb8b594e8a0b194f`。原包 45 个成员均保留，原成员哈希详见 `SOURCE_BASELINE.json`。此次未修改原 ZIP、原仓、原服务或公网。

19 个运行时代码文件（core/src 全部、失败经验适配模块、原薄桥）保持源字节；修改仅涉及便携路径、派生字节固定、历史/当前边界和说明。原 33 成员结构、协议字段、签名校验和 Gate 没有放宽。

| 改动文件 | 原因 |
| --- | --- |
| `ACTIVE_ACCEPTANCE.json` | 历史出处改为逻辑名；明确派生包没有新人工验收，不授予权限。 |
| `BASELINE.json` | 保留原逐文件哈希和历史出处，用逻辑来源名替代机器路径；不作为当前授权。 |
| `CORE_CAPTURE.json` | 按本次33成员派生字节重建清单并标明非授权；原清单哈希另存来源记录。 |
| `DELIVERY_MEMBERS.json` | 重建便携包字节清单，标明非签名/非授权，不复用原验收结论。 |
| `DELIVERY_STATUS.md` | 改为便携派生的真实交付边界和当前入口。 |
| `core/docs/PROVENANCE.md` | 机器出处改为逻辑上游包名，保留原来源成员及哈希/规范化规则。 |
| `core/docs/USAGE.md` | 文档路径替换为需由当前受信初始化解析的占位符/环境变量；全部协议字段保留。 |
| `core/tests/test_evidence_projection.py` | 未随原ZIP包含的历史R3对照改为包内逻辑参考位置；不伪造旧对照，不宣称完整套件可用。 |
| `core/tests/test_validation.py` | 负例绝对路径由当前系统根动态派生，保留越界拒绝断言。 |
| `docs/FAILURE_EXPERIENCE.md` | 同步派生字节及历史人工PASS边界说明，保留全部失败经验约束。 |
| `samples/README.md` | 换为包根相对入口和全新外部输出命令，解释新TEST_ONLY身份与预期失败。 |
| `tests/test_failure_experience.py` | 清单定位改为包内；更新派生清单固定哈希；缺失历史桥使用逻辑参考路径，核心流程断言不变。 |
| `tools/delivery_tools.py` | 标明字节检查非授权，将再打包目标命名为便携派生以免混淆原版。 |
| `tools/run_failure_sample.py` | 固定本次派生测试和清单哈希，明确派生结果，不冒称原字节未变。 |

新增文件：`README.md`（中文使用说明）、`requirements.txt`、`requirements-dev.txt`、`SOURCE_BASELINE.json`、`CHANGELOG_PORTABLE.md`、`PORTABLE_VALIDATION.json`。

没有删除原契约或协议，也没有复制任何原运行授权、私钥、会话/日志/业务状态。原资料只有部分合同和旧R3/旧桥的哈希引用，源ZIP未带其原件；引用保留并明确标为历史/未随包交付，未用假文件补齐。

本次检查：在另一个带空格的目录、清洁白名单环境中以同一 Python/cryptography 对照运行源包与派生包 flow01；两者均退出0，保留原命令FAILED/退出7，当前上下文 dispatch_allowed=false。派生 CLI/桥帮助入口退出0，五个越界输出路径拒绝用例通过；执行前后固定包字节未改变。详情见 `PORTABLE_VALIDATION.json`。

限制：未跑完整历史测试套件、flow02/03、模型、压力、生产身份部署或C06；不宣称人验、独立审计或生产PASS。原版人工PASS不转移；字节清单不是授权或签名。
