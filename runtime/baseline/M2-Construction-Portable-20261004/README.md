# 施工版便携清洁包

这是 `CK-FINAL-20260928-01` 的源码便携派生版 `CK-FINAL-20260928-01-portable-20261004`。它提供 Python 治理核心、受控工具桥和失败经验复用样例。无需原机器目录、C06、模型服务、数据库、账号或旧凭据。

**原版 2026-09-28 人工 PASS 不转移到本次派生包。** 本包未添加开源许可证；原有来源归属保留。来源 ZIP 和原哈希在 `SOURCE_BASELINE.json`，逐文件改动在 `CHANGELOG_PORTABLE.md`。验收范围见 `PORTABLE_VALIDATION.json`。

## 1. 环境和安装（Windows PowerShell）

需要 Python 3.11 或以上以及 `cryptography>=41`。本次实际使用 Python 3.13.11 / cryptography 46.0.3；其它系统或版本未在本轮验证。示例本身不需要 pytest；开发测试需要 requirements-dev.txt 中的 pytest。包不带 Python、二进制依赖或离线 wheel，首次安装依赖通常需要网络。

解压到任意可写文件夹（允许空格），进入包含此 README 的包根，再运行：

```powershell
python --version
$packageRoot = (Get-Location).Path
$venvRoot = Join-Path (Split-Path $packageRoot -Parent) 'construction-env'
python -m venv "$venvRoot"
$python = Join-Path $venvRoot 'Scripts/python.exe'
& $python -m pip install -r ./requirements.txt
& $python -c "import sys, cryptography; print(sys.version); print(cryptography.__version__)"
```

若系统只有 `py -3`，第一、四行的 `python` 改为 `py -3`。虚拟环境放在包外；不需要激活它，不修改全局 Codex 或 Python 设置。已装好兼容依赖时可以直接使用现有解释器并把 `$python` 设为 `(Get-Command python).Source`。不要在 `core/` 内创建虚拟环境、缓存或额外文件，核心完整目录有严格的 33 成员检查。

## 2. 运行一个独立示例

仍在包根运行，使用上一节的 `$python`：

```powershell
$sampleOut = Join-Path (Split-Path (Get-Location).Path -Parent) ('construction-sample-' + [guid]::NewGuid().ToString('N'))
& $python -B ./tools/run_failure_sample.py --output "$sampleOut"
Get-Content -Raw (Join-Path $sampleOut 'flow01/flow-result.json')
```

每次使用全新输出目录；该目录必须在包外，不能是包的父目录，不能含符号链接或 Windows 重解析点。目录由脚本创建，请勿提前创建最后一级目录。样例通常数秒至几十秒结束。

它执行既有 flow01：新建 TEST_ONLY 身份和签名授权 → 运行有意失败的固定 TEST → 保留退出 7 的 FAILED 原回执 → 原授权过期 → 新任务以新授权读取失败经验 → 经新进程生成仅供建议的上下文。桥返回 2 是前半段预期，整个样例最终应退出 0。结果应包含 `original_command_status: FAILED`、`original_command_exit: 7`、`dispatch_allowed: false`、`human_acceptance: NOT_CLAIMED`。

**新身份如何初始化和签名：** 入口调用包内 `tests/test_failure_experience.py` 的既有 `make_real_case()` 与 `RealCase.signed_scope()`。它用 Ed25519 在内存生成全新私钥，写公开 pin 和当前机器解析出的配置路径，按既有规范化 JSON 规则签当前 TEST_ONLY 范围，再由原 Controller 校验。私钥不落盘、不复用旧身份；输出内的测试授权与证据也不要作为分发包再分享。CLI 本身不提供生产身份安装或签名命令。

## 3. 查看入口和协议

```powershell
$packageRoot = (Get-Location).Path
$env:PYTHONPATH = (Join-Path $packageRoot 'src') + [IO.Path]::PathSeparator + (Join-Path $packageRoot 'core/src')
$env:PYTHONDONTWRITEBYTECODE = '1'
& $python -B -m m2_construction.cli --help
& $python -B ./tools/native_b_runtime.py --help
```

完整字段、请求样式和 Gate 规则见 `core/docs/USAGE.md`；失败经验约束见 `docs/FAILURE_EXPERIENCE.md`。这些协议文档中的尖括号值是模板，不是可直接执行的配置。框架在运行时要求规范绝对路径，这是安全绑定要求；便携表示路径从当前包根/显式参数/环境变量解析，不内置原机器路径。

| 配置/参数 | 含义与要求 |
| --- | --- |
| `--output` | 样例全新外部输出根；自动生成工作区、状态、公开测试 pin 和配置。 |
| `workspace_root` | 本次允许治理的工作区，由当前路径解析；不是此源码包固定路径。 |
| `state_root` | 当前可信状态目录，必须位于工作区外；不能清空来绕过已消费操作。 |
| `pin_path` / `expected_pin_sha256` | 新 TEST_ONLY 公开 pin 及预先审核的精确哈希。 |
| reviewer / CEO pins | 真实独立角色的公开 pin；高级审计/发布协议需要，flow01 不模拟这些验收。 |
| `--config-sha256` / `--binding-sha256` | 调用前固定并审核的精确输入哈希，不可由请求自选/临时改写。 |
| `M2_TRUSTED_INPUTS` | 高级文档示例使用的当前受信公共输入目录；样例不需要设置。 |
| `M2_REVIEWED_CONFIG_SHA256` 等 | 高级示例使用的独立审核后配置哈希；不是密钥，不能用请求内容自证。 |
| `PYTHONPATH` | 仅当前进程的包内 `src` 与 `core/src`；示例入口自行解析包根。 |

`CORE_CAPTURE.json` 与 `DELIVERY_MEMBERS.json` 为当前派生字节清单，**不是签名或授权**。路径文档和测试适配造成哈希变化，已在样例固定常量中更新为本包哈希。原 runtime/Gate 没有放宽；后续编辑任一固定成员会被拒绝。不要为了运行随手重算哈希绕过检查，应形成新派生版并复核。`BASELINE.json` 与 `ACTIVE_ACCEPTANCE.json` 只是历史出处/边界索引，不会读取原机器控制文件或恢复旧授权。

## 4. 常见失败

| 提示/位置 | 处理 |
| --- | --- |
| 找不到 Python / `ModuleNotFoundError: cryptography` | 使用上一节的 `$python` 并在同一虚拟环境安装依赖。 |
| `CANONICAL_ABSOLUTE_PATH_REQUIRED` | 输出必须由当前路径/参数解析为规范绝对路径。 |
| `FRESH_EXTERNAL_OUTPUT_REQUIRED` | 换一个不存在的包外输出目录；不要覆盖上次证据。 |
| `LINK_OR_REPARSE_POINT` | 选普通目录，避开链接/联接点。 |
| `PINNED_INPUT_CHANGED` / `CORE_BYTES` / `EXACT_CORE_33` | 包被修改、成员增减或产生缓存；从清洁 ZIP 重新解压，保留失败原件。 |
| Gate 拒绝、旧授权到期、UNKNOWN | 按原回执定位；不能改成 PASS 或重放原操作。需要新的受信当前授权。 |
| 返回栈/断言失败 | 留存本次输出目录及错误；不要删除失败记录后冒充通过。 |

具体回执和上下文位置见 `flow01/flow-result.json` 的引用；测试过程记录在同输出的 `flow01/test-processes/`，状态/回执在其 `state/` 下。样例数据是本次合成数据，原历史日志/会话均不在交付包内。

## 5. 范围与已知限制

- 本次只验证离线 flow01、帮助入口、包字节和路径清洁度，并对动态绝对路径拒绝测试作最小回归；不等于全量/压力/模型/长期运行/生产验收。
- 全部核心和失败经验测试源码保留供审阅。`test_file_proof_real_project_and_same_cache_load` 需要未随原 ZIP 交付的 R3 历史对照，`--baseline-red` 需要未随原 ZIP 交付的前版桥。对应路径改为包内逻辑 `reference-inputs`，文件未伪造，不能把当前版本当作旧对照。因此不宣称开箱可跑完整历史测试套件。
- 实际宿主接入须由操作者建立当前身份、独立审查、任务范围、状态保护、租约和审计；包没有一个通用生产初始化向导，也不携带旧部署配置/私钥/授权。
- 只保护明确接入 Controller/工具桥的操作。它不是全局 Codex 工具拦截器、OS 沙箱或任意进程的安全隔离；不把样例 PASS 当作真实业务授权。
- UNKNOWN 保留原操作 ID，不自动重放；记忆和失败经验仅给建议，不提升权限。C06、旧服务、公网和业务状态不属于本包运行范围。
