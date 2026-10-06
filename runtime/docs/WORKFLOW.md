# 从项目知识到完整治理链

先完成 [START_HERE](../START_HERE.md) 中的 `doctor` 和项目知识准备。此包装层提供入口与资料，不自动组织完整主控。宿主可以是能调用命令的 AI 环境，也可以由操作者手动组织；它必须负责真实身份映射、范围与预算、模型调用以及独立审查。

## 先分清两份配置

| 配置 | 内容 | 能证明什么 |
|---|---|---|
| `project.json` | 需求、设计、代码、测试、决策、问题、记忆、证据的显式来源 | 本次读取了哪些字节，有哪些登记的缺口；不是运行授权 |
| `trusted-bootstrap.json` | 工作区、外部状态目录、固定公钥 pin 与其哈希 | CLI 连接的信任配置；还须当前有效 Scope、请求与对应证据 |

两者都由当前项目提供，包中不附可用于真实项目的历史授权、私钥或状态。工程迁移后应重新审核路径、解释器和配置哈希，不复制原机器绝对路径。

`readiness` 会检查事先固定的 config 哈希和对应 pin，只读辨认入口配置等级；不会建立账本：

```text
python -I -B m2.py readiness --config "/absolute/control/trusted-bootstrap.json" --config-sha256 "<固定64位小写SHA256>"
```

| 原配置 schema | 已装配的配置项 | 尚不能据此声称 |
|---|---|---|
| `M2_CONSTRUCTION_CLI_CONFIG_1` | Root pin；基础执行、测试、冻结、作者证明等原入口 | 已装配独审回交、CEO 接受或全链验收 |
| `M2_CONSTRUCTION_CLI_CONFIG_2` | CONFIG_1 加 reviewer pin，可接内部回交 | 已装配 CONFIG_3 发布链、已完成真实独审 |
| `M2_CONSTRUCTION_CLI_CONFIG_3` | Root、父 reviewer、子 reviewer、CEO 的固定 pin | 审查通过、CEO 已接受、已获发布权限或已发布 |

pin 为公钥信任文件，不是私钥。可信操作者需要在请求材料之外保存经过审核的 config 字节哈希。不要把调用时临时计算的文件哈希当作独立信任依据。当前内核信任域是 `TEST_ONLY`，完整链路同样不自动取得真实业务发布权限。

## 由宿主组织的顺序

1. **理解项目并固定范围。** 对照项目资料与原证据，记录本次目标、可信对照版本、候选工作区、约束、未决项、累计预算及必要测试。缺资料或冲突须先限定结论。
2. **建立当前信任与授权。** 可信操作者在工作区外准备状态与公钥 pin，外部签署当前 Scope。作者、独立审查者与 CEO 的身份绑定由宿主和可信签发方负责，CLI 不自签授权。`grant` 验证签名后登记；首次登记可建立配置指定的账本。
3. **受控施工。** 通过 `create` / `patch` 进行当前范围允许的文件操作，使用预先签定的 `command` 执行 TEST/BUILD。命令不能从请求临时指定任意 argv；解释器、参数、cwd、环境、时间和跟踪文件以签署 Scope 为准。
4. **真实测试并冻结。** 保留原始命令日志和回执；检查被测源码、测试、构建输出与候选字节一致。`freeze` 绑定实际 TEST/BUILD 操作与文件。冻结不等于审查通过。
5. **作者证明与非作者审查。** 外部可信签发方核验作者并签署作者证明，由 `attest` 记录。独立审查者阅读固定候选、需求、测试覆盖和原回执，签署绑定当前候选的 review；程序验证签名与绑定，不自动产生审查意见。
6. **局部裁决与内部回交。** `return` 在原规则要求的局部 GO 和签署回交指令下进行单次 `INTERNAL_PARENT_ONLY` 回交。它不授予发布权限。CONFIG_3 中此步骤使用子 reviewer pin。
7. **父集成与接受。** 父级核对回交来源、集成后字节及影响范围，再完成父级测试、冻结、作者证明与独审。外部 CEO 接受及 Root 签署的角色证明绑定父候选、review 和回交记录；`ceo-accept` 验证后记录接受事件。
8. **发布前裁决、单次发布与 POST。** `pre-release` 只读返回 PASS/FAIL/INDETERMINATE；PASS 仍不自动派发。另行签发的单次 release lease 才可交给 `release` 消费。`post-release` 只读复核目标树；`post-verify` 在复核通过后记录一次 POST 事件。它们都不替代用户约定的人工审阅。

每阶段保留原失败、未覆盖项、UNKNOWN 与预算累计。新 run 或新会话继续同一任务时，从原账本、原操作 ID 和当前状态恢复。当前包装层没有“启动后自动一路做到 CEO PASS”的命令。

## 原 CLI 的统一入口

所有原命令通过 `kernel` 转接，参数与请求 schema 保持原定义：

```text
python -I -B m2.py kernel --config "/absolute/control/trusted-bootstrap.json" --config-sha256 "<固定64位小写SHA256>" status --request "/absolute/control/status-request.json"
```

`status-request.json` 的只读请求示例：

```json
{"schema":"M2_CONSTRUCTION_STATUS_REQUEST_1"}
```

| 阶段 | 原 CLI 子命令 |
|---|---|
| 授权与效果 | `grant`、`create`、`patch`、`command` |
| 候选与作者 | `freeze`、`attest` |
| 内部回交 | `return` |
| 查询 | `status` |
| 父级接受与发布 | `ceo-accept`、`pre-release`、`release`、`post-release`、`post-verify` |

使用当前可信操作者准备的请求，不用历史请求补齐缺少的授权。请求格式、签署字段、路径约束和回执含义请读 [原 CLI 文档](../baseline/M2-Construction-Portable-20261004/core/docs/USAGE.md)。该文中的配置 JSON 是结构示意，不是已签发实例；其中过期的示例时间也不能直接使用。

## 原工具桥的统一入口

原桥便于宿主用参数提交 create/patch/command/freeze/status，以及失败经验 `prepare-context`；桥不提供独审签署、CEO 接受或完整发布命令。完整链仍使用前述 `kernel`。

```text
python -I -B m2.py tool --binding "/absolute/control/binding.json" --binding-sha256 "<事先固定的binding SHA256>" status
```

binding 由可信宿主准备并固定，包含当前任务、阶段、原 CLI 配置哈希、内核 capture、解释器字节和控制目录。迁移后核对其实际绝对路径；固定内核位于包内 `baseline/M2-Construction-Portable-20261004/core`，原 `CORE_CAPTURE.json` 位于该父包根。不要把包装层根目录当作原内核根。

桥输出仍需核对实际 native 回执和原始宿主调用证据。超时或 UNKNOWN 不能通过换 operation ID 自动重跑。失败经验只供参考，详见 [原失败经验文档](../baseline/M2-Construction-Portable-20261004/docs/FAILURE_EXPERIENCE.md)。
