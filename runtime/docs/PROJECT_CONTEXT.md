# 配置项目知识与记忆

治理框架需要知道哪些规则允许执行；接手 AI 还需要知道项目本身要做什么。这里的 `project.json` 负责后者：显式登记文件、来源哈希和适用条件，把读到的资料连同缺口交给 AI。它不执行来源内容，不写入原内核 MemoryStore，也不替代治理授权。

## 1. 选定要提供的文件

| `kind` | 适合放什么 |
|---|---|
| `requirements` | 当前需求、任务边界、接受条件 |
| `design` | 架构、接口契约、领域规则、业务口径 |
| `code` | 本次相关代码入口和实现文件 |
| `tests` | 测试清单、相关测试文件、覆盖说明 |
| `decisions` | 已确认决策及其理由、来源与适用版本 |
| `known_issues` | 已知缺陷、未决问题、已排除假设与原证据引用 |
| `memory` | 项目交接记忆、当前约束、恢复检查点 |
| `evidence` | 原日志、报告或回执的非敏感文本，及证据索引 |

每个来源必须是项目根内明确的普通 UTF-8 文本文件；同一文件只登记一次。没有自动扫描或目录展开，不接受通过 `..` 越出根目录、链接、网络路径或敏感文件路径。路径中可以有空格和中文。PDF、图片或大型二进制不由此加载器解析，应由适当工具先提取并核对，再登记带原件引用的文本。

上下文输出会包含所选文件内容。只选确实需要交给 AI 的资料，先处理其中的凭据或私钥；工具的敏感文件名和 PEM 私钥检查不等于完整脱敏服务。

当前限制为最多 128 个来源、单文件 256 KiB、合计 1 MiB，配置文件最多 128 KiB。超限时缩小选择或准备可回到原件核验的证据索引，不能把截断后的摘要当作完整原件。

## 2. 建立新配置

先在包外准备项目根目录和配置父目录，再运行：

```text
python -I -B m2.py project-init --root "/absolute/path/Example Project" --config "/absolute/path/M2 Runtime/project.json" --project-id "example-project" --goal "核对本次需求、代码与测试，保留未核事项" --source "requirements=docs/requirements.md" --source "code=src/main.py" --source "tests=tests/test_main.py"
```

Windows PowerShell 和 macOS/Linux 的完整写法见 [START_HERE.md](../START_HERE.md)。`--source` 可以重复；只替换为项目中实际存在的文件。目标配置必须不存在，工具不覆盖旧配置。项目根与配置在 Windows 上须位于同一盘，生成器会将 `project_root` 保存为相对配置目录的路径，便于把二者按相同目录关系一起迁移。

生成器读取这些文件、计算实际字节 SHA256，写出 schema `portable-project-context-v1`。它把来源初始登记为 `current` / `reference`，用 `sha256:<实际哈希>` 标记 revision；这些默认值只是登记，不是内容正确或确实最新的认证。应继续完成下一步的人工或宿主审阅。

缺少某类资料时，配置仍可建立，输出会列出 `missing_roles`。不要为了得到“完整”状态写虚假文件或编造既有记忆。

## 3. 审阅来源的适用性

配置顶层主要字段：

| 字段 | 含义 |
|---|---|
| `schema_version` | 固定为 `portable-project-context-v1` |
| `project_id`、`goal` | 项目标识和本次目标；不是 Scope 或任务授权 |
| `project_root` | 相对配置目录的项目根位置；来源再相对此根定位 |
| `sources` | 精确来源列表 |
| `not_applicable` | 明确不适用的来源类别列表，默认 `[]`；例如 `[{"kind":"design","reason":"具体理由"}]` |
| `execution_authority`、`human_acceptance` | 生成值分别为 `false`、`NOT_CLAIMED`；输出不会由配置自报变成授权或 PASS |

每个 `sources` 条目的字段：

| 字段 | 填写方式 |
|---|---|
| `id` | 唯一来源 ID；供冲突和替代关系引用 |
| `kind` | 上述八类之一 |
| `path` | 项目根内的具体相对文件路径，推荐 `/` 分隔 |
| `sha256` | 已登记文件的实际字节哈希，64 位小写十六进制 |
| `revision` | 可追溯版本文字；生成器默认使用内容哈希，可补充经核对的版本标签 |
| `status` | `current`、`draft`、`expired` 或 `superseded` |
| `applicability` | 必须包含 `conditions` 和 `limitations` 两个字符串列表，记录适用条件及限制 |
| `claim_type` | `reference`、`assumption` 或 `unverified_report`；不会自动升级为已证事实 |
| `critical` | 布尔值，标记问题是否涉及关键资料；不让其他缺失或错误悄悄通过 |
| `conflicts` | 与本来源冲突的其他来源 ID 列表 |
| `supersedes` | 本来源明确替代的旧来源 ID 列表 |

以下片段可以用于说明适用性；把它填写到正确来源中，保留生成的真实 ID、路径和哈希：

```json
{
  "status": "draft",
  "claim_type": "unverified_report",
  "critical": true,
  "applicability": {
    "conditions": ["仅适用于所引用候选和测试环境"],
    "limitations": ["原测试报告尚未复核，不能作为通过结论"]
  },
  "conflicts": [],
  "supersedes": []
}
```

该片段不是完整来源对象，不能单独作为配置运行。`draft` 和 `unverified_report` 的内容可以进入上下文，但仍标为未经事实认证的参考。AI 必须保留其声明级别。

`expired`、`superseded` 或被 `supersedes` 指向的来源会被排除内容；显式冲突的双方同样排除，并记录问题。若已有有效替代覆盖该类别，旧来源的明确过期或替代本身不必使整份上下文不完整。工具不自动分析语义冲突，也不根据文件年龄、当前时间或 Git HEAD 判断过期；关系与适用条件需要操作者根据证据维护。不得把“更晚生成”当作“更可信”。

只有某类资料确实不适用时，才填写 `not_applicable` 并给具体理由。“暂时没有拿到”是缺失，不能写成不适用；同一类别不能一边登记来源、一边声明不适用。完整性只是这些登记条件满足，不代表资料足以证明项目正确。

## 4. 读取和交接

```text
python -I -B m2.py start --project "/absolute/path/M2 Runtime/project.json"
python -I -B m2.py context --config "/absolute/path/M2 Runtime/project.json" --output "/absolute/path/M2 Runtime/context-01.json"
```

不传 `--output` 时 JSON 输出到终端；传入时要求包外新文件且父目录已经存在。输出包含目标、各来源的元数据与纳入内容、`observed_sha256`、`hash_status`、`exclusion_reasons`、`missing_roles` 与 `issues`。

| 输出 | 含义 |
|---|---|
| `CONTEXT_READY_FOR_REVIEW` | 登记的类别被来源或有效不适用声明覆盖，且本次加载无待处理问题；现在可以审阅资料 |
| `PROJECT_CONTEXT_INCOMPLETE` | 有缺失类别、来源读取或哈希错误、显式冲突等问题；按输出补证 |
| `verification=UNTRUSTED_PROJECT_REFERENCE` | 即使哈希 MATCH，这份内容也只是未认证的项目参考 |
| `execution_authority=false` | 项目上下文没有授予任何治理效果权限 |

`start` 将前一种状态包装为 `PROJECT_CONTEXT_READY`，并附环境检查；含义仍只是项目参考准备好供审阅。`context` / `start` 在资料不完整时返回退出码 3 并输出缺口；`project-init` 成功写出索引可以返回 0，仍应查看输出状态，不能只看退出码。

## 5. 更新与恢复

文件发生变化后，先读原件并判断变化是否影响当前任务，再更新来源哈希、revision 和适用条件。保留旧配置与旧报告，建议为新的已审阅资料集建立新配置文件；不通过直接重算哈希掩盖未知更改。工具不会自动刷新哈希或替你调解冲突。

接手 AI 应先从目标、约束、已确认决策和已知问题恢复，再回到关键原证据核验。项目记忆可以说明当前任务累计预算、未决操作 ID、失败原因与恢复位置，但恢复授权和真实状态仍由当前治理账本与有效签署材料决定；不能从旧记忆复制过期权限。

此配置不能替代独立审查者阅读相关实现与调用方，也不能用来认定全部测试已经存在、已经执行或已经通过。继续施工前转到 [WORKFLOW.md](WORKFLOW.md)。
