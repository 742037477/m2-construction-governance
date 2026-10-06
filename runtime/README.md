# M2 施工版便携启动包

**从 [START_HERE.md](START_HERE.md) 开始。唯一入口是包根 `m2.py`。**

文档增补 R2 附带 [架构因果说明](docs/ARCHITECTURE_CAUSALITY.md)：各节点为何存在、如何形成约束、缺少后的风险、项目记忆与治理证据的分工，以及与 C06 / 三道门图的对应边界。运行时代码与上一包相同。

此包为 Python 施工治理框架增加启动入口、环境与文件检查、项目资料索引和操作指南。适合已有 AI 宿主或可信操作者接入自己的开发项目；宿主负责理解需求、组织施工、调用模型、安排独立审查和验收。

```text
python -I -B m2.py
python -I -B m2.py doctor
python -I -B m2.py start --project "/absolute/path/to/project.json"
```

Windows 使用已安装的 Python 3.11+；macOS/Linux 通常使用 `python3`。安装依赖、包含空格的路径写法和完整步骤见 [启动指南](START_HERE.md)。无参数显示帮助；`start` 只检查入口并读取配置的项目资料，不自动施工、签发授权、调用审查者或判定项目通过。

| 你要做什么 | 入口 |
|---|---|
| 第一次收到包，检查 Python、依赖和文件 | `doctor` |
| 让 AI 获取已配置的项目知识 | `start --project …` 或 `context --config …` |
| 为自己的项目建立资料索引 | `project-init`，见 [项目知识配置](docs/PROJECT_CONTEXT.md) |
| 查看完整施工流程及角色责任 | `workflow`、[流程指南](docs/WORKFLOW.md) |
| 检查已有可信配置达到哪一级 | `readiness --config … --config-sha256 …` |
| 运行隔离的失败经验样例 | `sample --output …`，见 [启动指南](START_HERE.md) |
| 使用原内核全部 CLI 命令 | `kernel …`，见 [原 CLI 文档](baseline/M2-Construction-Portable-20261004/core/docs/USAGE.md) |
| 使用原工具桥 | `tool …`，见 [流程指南](docs/WORKFLOW.md) |

包内 `baseline/M2-Construction-Portable-20261004/` 保留 2026-10-04 父包的 53 个成员原字节；其中治理内核未由本包装层改写。旧文档中的原机路径、历史状态和命令仅用于追溯，当前启动按包根指南执行。原 CK-FINAL-20260928-01 的人工 PASS 只覆盖当时版本与验收范围，不自动扩展到此包装层、其他平台或你的项目。

使用前请记住三个边界：

- 本包不是通用 Agent 自动编排平台，也不是 OS 沙箱；绕过规定入口的工具调用不受这里的程序门控保护。
- 当前内核与样例采用 `TEST_ONLY` 信任域。配置完整、测试通过、冻结候选与发布前裁决分别有不同含义，见 [状态说明](docs/STATUS_MEANING.md)。
- 项目记忆是带来源的参考资料。哈希证明读取字节是否一致，不证明文档的叙述正确；旧报告、缺失资料和冲突都要保留其证据级别。

AI 接手先读 [AGENTS.md](AGENTS.md)。排障见 [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)，业务审查见 [REVIEW_CHECKLIST.md](docs/REVIEW_CHECKLIST.md)，包内方法来源见 [methods/README.md](methods/README.md)。
