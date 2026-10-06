# 复现：先建立自己的记录，再讨论治理效果

以下步骤供读者在自己的隔离研究目录执行。本文编写时仅静态核对源码与已有记录，没有重新运行测试或服务。首次复现可以只完成入口、项目资料和样例；完整治理链需要宿主另外组织可信签发与独立角色。

## 1. 固定版本和复现范围

本公开派生版为 `M2-RESEARCH-20261006-RC1`。记录你下载的发行物哈希或仓库 commit、`runtime/PORTABLE_VALIDATION.json`、操作系统、Python 与依赖版本。保留未修改的公开版 `runtime/` 作为对照；实验改动放独立派生目录，不把修改过的清单说成原版校验通过。

公开版保留 R2 运行时代码、53 个嵌入父包成员与既有验证记录的原字节；三个方法参考文档改为公开表述并更新包装清单。原记录可用于识别相同代码的既有验证范围，不能证明这个新发行物又运行过一轮测试。

已有证据见 [VALIDATION.md](../runtime/VALIDATION.md) 和 [PORTABLE_VALIDATION.json](../runtime/PORTABLE_VALIDATION.json)：便携入口仅有 Windows/Python 3.13.11/cryptography 46.0.3 的限定运行记录；macOS/Linux 未实机验证。R2 是文档增补，复用相同运行时代码的 R1 记录。2026-09-28 原内核人工 PASS 不扩展到便携新版本、此仓库或你的项目。

包内要求 Python 3.11+、`cryptography>=41`；最低声明版本不等于所有组合均已验证。普通入口和样例不需要 pytest。选择一套确实安装的 3.11+ 解释器，把环境与输出放在 `runtime/` 外。

## 2. 环境准备与 doctor

以下使用包含空格的示例路径。替换为自己的真实路径，选择一个**尚不存在**的研究目录；后续重复运行使用新的输出文件/目录，保留首轮失败。

Windows PowerShell，从仓库根目录开始：

```powershell
Set-Location -LiteralPath 'C:\Work\M2 Research'
$M2Lab = 'C:\Work\M2 Research Lab 01'
New-Item -ItemType Directory -Path $M2Lab -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path "$M2Lab\project", "$M2Lab\control" | Out-Null
py -3.13 -m venv "$M2Lab\.venv"
$M2Python = "$M2Lab\.venv\Scripts\python.exe"
& $M2Python -m pip install -r '.\runtime\requirements.txt'
& $M2Python -I -B '.\runtime\m2.py' doctor
```

`py -3.13` 要求本机已经安装该版本；也可用另一套已安装 3.11+ 解释器的完整路径创建环境，并记录差异。

macOS/Linux shell，对应写法如下；这是待读者验证的使用路径，不能作为实机通过声明：

```sh
cd '/absolute/path/M2 Research'
M2_LAB='/absolute/path/M2 Research Lab 01'
mkdir "$M2_LAB"
mkdir "$M2_LAB/project" "$M2_LAB/control"
python3 --version
python3 -m venv "$M2_LAB/.venv"
M2_PYTHON="$M2_LAB/.venv/bin/python"
"$M2_PYTHON" -m pip install -r './runtime/requirements.txt'
"$M2_PYTHON" -I -B './runtime/m2.py' doctor
```

保存本轮命令、标准输出/错误和退出码。`STARTUP_READY` 只表示本次环境与包一致性检查通过。遇到 `BLOCKED` 先核对原因，不删除校验或修改清单绕过。包内局部一致性检查不能代替可信发行物来源或 OS 权限保护。

## 3. 配置一个最小项目资料集

下面创建一个明确标为演示的需求文本，只登记这一份来源，目的是观察缺口如何呈现。它不会伪造完整项目或测试证据。

Windows PowerShell，沿用上一步变量：

```powershell
Set-Content -LiteralPath "$M2Lab\project\requirements.md" -Encoding utf8 -Value '# 研究演示：只核对项目资料加载，尚无业务实现或验收结论。'
& $M2Python -I -B '.\runtime\m2.py' project-init `
  --root "$M2Lab\project" --config "$M2Lab\control\project.json" `
  --project-id 'research-case-01' --goal '观察明确来源与缺失类别的呈现' `
  --source 'requirements=requirements.md'
& $M2Python -I -B '.\runtime\m2.py' start --project "$M2Lab\control\project.json"
& $M2Python -I -B '.\runtime\m2.py' context `
  --config "$M2Lab\control\project.json" --output "$M2Lab\control\context-01.json"
```

macOS/Linux shell：

```sh
printf '%s\n' '# 研究演示：只核对项目资料加载，尚无业务实现或验收结论。' > "$M2_LAB/project/requirements.md"
"$M2_PYTHON" -I -B './runtime/m2.py' project-init \
  --root "$M2_LAB/project" --config "$M2_LAB/control/project.json" \
  --project-id 'research-case-01' --goal '观察明确来源与缺失类别的呈现' \
  --source 'requirements=requirements.md'
"$M2_PYTHON" -I -B './runtime/m2.py' start --project "$M2_LAB/control/project.json"
"$M2_PYTHON" -I -B './runtime/m2.py' context \
  --config "$M2_LAB/control/project.json" --output "$M2_LAB/control/context-01.json"
```

根据实现，本例应得到 `PROJECT_CONTEXT_INCOMPLETE`，并列出另外七类 `missing_roles`；`start/context` 退出码 3。这是本例预期的资料缺口，不应修成虚假的“完整”。记录实际输出是否符合预期，不把预期写成已经观察到的结果。

接入真实项目时，按 [CONFIGURATION.md](CONFIGURATION.md) 选择实际文件，审阅来源级别、适用条件、冲突与替代关系。没有取得的资料仍为缺失；确实不适用的类别才可填写有理由的 `not_applicable`。不要扫描或导出整仓凭据。

## 4. 运行隔离的原失败经验样例

Windows PowerShell：

```powershell
& $M2Python -I -B '.\runtime\m2.py' sample --output "$M2Lab\sample-01"
```

macOS/Linux shell：

```sh
"$M2_PYTHON" -I -B './runtime/m2.py' sample --output "$M2_LAB/sample-01"
```

输出目录执行前必须不存在。样例使用隔离的 `TEST_ONLY` 临时身份与当次样例授权，执行原 flow01：保留真实 FAILED/exit 7，再在新任务与新进程中读取失败经验。实际检查 `flow01/flow-result.json` 及其回执引用，不能只看外层退出码。

若得到 `DEMO_COMPLETED`，结论限于该次样例。它不是你的项目测试、独立审查或全链验收，也没有建立通用 Agent 自动主控。样例当前不需要模型；不要从它推断某个模型提供商已经接入或通过验证。

## 5. 完整治理研究须由宿主装配

先读 [流程指南](../runtime/docs/WORKFLOW.md) 和 [原 CLI 请求协议](../runtime/baseline/M2-Construction-Portable-20261004/core/docs/USAGE.md)。由可信操作者准备本次 bootstrap、公钥 pin、提前审核的配置哈希与当前签名 Scope。用 `readiness` 辨认 CONFIG_1/2/3；没有相应资料时把完整链标为未运行，不照抄样例授权。

研究者或宿主依次组织：当前范围授权、受控施工、真实 TEST/BUILD、冻结与作者证明、非作者审查、内部回交、父集成验证、CEO 接受、PRE、单次 release 和 POST。`kernel` 保留全部原 CLI 命令；`tool` 仅转接原桥能力。入口不替你调用模型或签发 review。

测试须对应冻结候选真实字节。尤其检查 Maven `-f`、外部源码目录、生成文件与构建产物；另一份仓库通过不能证明本候选通过。测试清单区分 PASSED/FAILED/NOT_RUN，未运行不能写成“没有该测试”。字段兼容性应实际核查类型、SDK 与调用方，不能靠字段名称猜测。

run1/run2/run3 保留同一总任务预算、原失败和未决记录；UNKNOWN 先按原 ID 查询并核实，不自动换 ID 重试。完整链研究的结论仍应列出未覆盖范围，不能把签名有效等同于审查自然语言正确。

## 6. 回报与对照

按照 [研究回报模板](RESEARCH_AGENDA.md#复现回报模板) 提交自己的环境、步骤、预期、实际结果与最小证据。负面结果、未复现和平台限制同样有价值。

提出修复时先保留可信对照，以相同输入、历史、数据范围与必要配置比较，找第一个可证实差异后做最小修改。涉及随机模型输出时做少量同条件复测，并区分机制故障、模型判断和证据缺失。原始记录含敏感材料时，保留受控原件，公开可审阅的最小脱敏复现材料并说明删减范围。

当前文档未声称任何社区独立复现已成功。你的报告应只写实际执行到的阶段和实际观察到的结果。许可范围与商业使用条件以仓库许可文件为准。
