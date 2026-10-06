# 配置：项目知识与治理信任分开装配

先按 [复现步骤](REPRODUCING.md) 准备 Python，并运行 `runtime/m2.py doctor`。以下配置对应已有接口；`project-init`、`start` 和 `readiness` 都不会自动签发 Scope、调用模型或完成独审。

## 1. 两类配置解决不同问题

| 配置 | 回答的问题 | 创建与读取入口 | 是否授予执行权限 |
|---|---|---|---|
| `project.json` | 这个项目的需求、代码、测试和已知事实来自哪里？ | `project-init` 创建；`start --project` / `context --config` 读取 | 否，仅产生参考上下文 |
| `trusted-bootstrap.json` | 本次 CLI 连接哪个工作区、状态与固定公钥？ | 可信操作者准备；`readiness` / `kernel` 校验 | 配置本身不授权，还需当前有效签署材料 |

两类配置和实际状态放在 `runtime/` 外。建议给研究运行独立目录：

```text
M2 Research/                  仓库，runtime/ 保持固定
M2 Research Lab/              当前研究目录，使用你自己的绝对路径
  .venv/                     Python 环境
  project/                   本次项目文件
  control/                   project.json、请求和操作者准备的输入
  trusted-public/            可信公钥 pin；不要放进项目或状态目录
  state/                     持续治理账本；不要每个 run 重建
  sample-01/                 样例新输出，执行前必须不存在
```

路径只是布局示意。bootstrap 使用规范绝对路径；项目知识配置中的 `project_root` 则相对配置文件目录。Windows 的项目知识配置与项目根须在同一盘，以便生成相对关系。

## 2. 项目知识：显式文件与来源级别

用 `project-init` 指定项目根、目标与具体来源，避免手工填写错误哈希：

```text
python -I -B runtime/m2.py project-init --root "/absolute/lab/project" --config "/absolute/lab/control/project.json" --project-id "research-case-01" --goal "核对给定需求与实现，保留未核事项" --source "requirements=docs/requirements.md" --source "code=src/main.py" --source "tests=tests/test_main.py"
```

示例文件须真实存在，配置目标须是包外新文件且父目录已存在。Windows PowerShell 可使用 `& $M2Python`，macOS/Linux 使用 `"$M2_PYTHON"`；完整命令见 [REPRODUCING.md](REPRODUCING.md)。

实际 schema 是 `portable-project-context-v1`，字段定义见 [原项目配置说明](../runtime/docs/PROJECT_CONTEXT.md) 和 [project_context.py](../runtime/portable/project_context.py)。

| 字段 | 实际语义 |
|---|---|
| `schema_version` | 固定 schema 标识 |
| `project_id`、`goal` | 项目标识和本次理解目标，不能充当治理任务授权 |
| `project_root` | 相对配置目录定位项目根 |
| `sources` | 精确文件列表，不展开目录或通配符 |
| `not_applicable` | `[{"kind":"类别","reason":"真实不适用的理由"}]`；默认 `[]` |
| `execution_authority`、`human_acceptance` | 输出为 `false`、`NOT_CLAIMED`，不能由输入自报为 PASS |

`sources` 每项必填 `id`、`kind`、`path`、`sha256`、`revision`、`status`、`applicability`。`applicability` 必须有 `conditions` 和 `limitations` 字符串列表。可选项为 `claim_type`、`critical`、`conflicts`、`supersedes`。

- `kind`：`requirements`、`design`、`code`、`tests`、`decisions`、`known_issues`、`memory`、`evidence`。
- `status`：`current`、`draft`、`expired`、`superseded`。
- `claim_type`：`reference`、`assumption`、`unverified_report`。后两者不会因哈希匹配升级成事实。
- `conflicts` 和 `supersedes` 引用其他来源 ID；工具处理显式关系，不自动判断语义冲突或文档年龄。

生成器默认登记为 `current` / `reference`。这只是初始元数据，应审阅适用性再交给 AI。真正缺少资料时保留 `missing_roles`；“没拿到”不能改写为“不适用”。哈希表示实际字节与登记一致，不表示叙述真实或测试覆盖充分。

仅读取项目根内显式普通 UTF-8 文本，拒绝越界、链接及敏感路径等输入。当前限额为 128 个来源、单文件 256 KiB、总计 1 MiB、配置 128 KiB。输出含所选文件内容，操作者须自行核对敏感信息；内置路径/私钥检查不是完整脱敏服务。

```text
python -I -B runtime/m2.py start --project "/absolute/lab/control/project.json"
python -I -B runtime/m2.py context --config "/absolute/lab/control/project.json" --output "/absolute/lab/control/context-01.json"
```

`CONTEXT_READY_FOR_REVIEW` 只表示本次登记与加载条件满足；`start` 将它包装为 `PROJECT_CONTEXT_READY`。缺资料或有问题时返回 `PROJECT_CONTEXT_INCOMPLETE`，`context/start` 退出码为 3。`project-init` 成功写出配置可以返回 0，仍须读 JSON 状态。所有内容保持 `UNTRUSTED_PROJECT_REFERENCE` 性质。

文件变化后先判断原因与适用性，保留旧配置，再登记经审阅的新哈希。不要自动重算哈希来隐藏未知更改；此加载器也不会自动向内核 MemoryStore 或 OrchestrationStore 写入项目知识。

## 3. 治理 bootstrap：固定信任入口

配置由可信安装者或宿主准备，并在请求材料之外提前保存审核过的精确字节 SHA256。格式与原命令协议见 [原 CLI 文档](../runtime/baseline/M2-Construction-Portable-20261004/core/docs/USAGE.md)；实际检查见 [cli.py](../runtime/baseline/M2-Construction-Portable-20261004/core/src/m2_construction/cli.py) 的 `_bootstrap`。

| 等级 | 实际字段 | 所支持的入口范围 |
|---|---|---|
| `M2_CONSTRUCTION_CLI_CONFIG_1` | `schema`、`workspace_root`、`state_root`、`pin_path`、`expected_pin_sha256` | 基础执行、测试、冻结、作者证明等原命令 |
| `M2_CONSTRUCTION_CLI_CONFIG_2` | 上述字段加 `reviewer_pin_path`、`expected_reviewer_pin_sha256` | 补内部回交 reviewer 配置 |
| `M2_CONSTRUCTION_CLI_CONFIG_3` | CONFIG_2 加 `child_reviewer_pin_path`、`expected_child_reviewer_pin_sha256`、`ceo_pin_path`、`expected_ceo_pin_sha256` | 补 CEO 接受与发布阶段配置；父、子 reviewer 分别绑定 |

所有路径须符合原 CLI 的规范绝对路径约束。状态在工作区外；CONFIG_3 的四个 pin 路径彼此不同，均在工作区和状态目录外。pin 是公钥信任文件，私钥不由 CLI 创建或保存。当前信任域为 `TEST_ONLY`，不是生产 Root。

有了真实配置及提前固定的哈希，才能运行：

```text
python -I -B runtime/m2.py readiness --config "/absolute/lab/control/trusted-bootstrap.json" --config-sha256 "<提前审核保存的64位小写SHA256>"
```

不要在派发时把请求可修改文件的即时哈希当成独立可信依据。`readiness` 只读验证 config 与 pin，不创建账本或评价当前 Scope/review。输出分别是 `EXECUTION_ONLY_CONFIGURATION`、`INTERNAL_RETURN_CONFIGURATION`、`FULL_CHAIN_CONFIGURATION_PRESENT`；前两者退出码 3，末者为 0。CONFIG_3 齐备仍不代表独审完成、CEO 接受或允许发布。

第一次有效 `grant` 可建立原内核账本；之后持续保留同一账本与累计预算。删除状态重新创建不是正常任务恢复方法。

## 4. 工具桥与迁移

`kernel` 转接完整原 CLI，`tool` 转接原桥。桥另需要 `CK_NATIVE_B_BRIDGE_BINDING_1` binding，固定当前任务、阶段、CLI config、解释器、内核 capture 和控制目录。它不是项目知识配置，也不会生成可信 bootstrap。

```text
python -I -B runtime/m2.py kernel --help
python -I -B runtime/m2.py tool --help
```

参数依据 [native_b_runtime.py](../runtime/baseline/M2-Construction-Portable-20261004/tools/native_b_runtime.py)。完整工作顺序见 [WORKFLOW.md](../runtime/docs/WORKFLOW.md)，不要从内部测试装配代码推定现有身份或授权可直接复用。

迁移机器时重新核对绝对路径、解释器字节与可信配置；项目资料可按原相对目录关系迁移，但仍要重新读取核验。记忆、配置或历史 PASS 不会替新环境建立权限。常见拒绝见 [TROUBLESHOOTING.md](../runtime/docs/TROUBLESHOOTING.md)。
