# 从这里启动

把完整 ZIP 解压到独立目录，保留包内文件布局。以下命令中的路径是示例，请换成自己的绝对路径。包目录只存程序和文档；Python 虚拟环境、项目配置、运行状态和输出都放在包外。

## 1. 准备 Python 和依赖

需要 Python 3.11+ 和 `cryptography>=41`；以包内 `requirements.txt` 为准。普通启动和样例不需要安装 pytest。不要在包内建立 `.venv`，不要改全局 `PYTHONPATH`。

Windows PowerShell：

```powershell
Set-Location -LiteralPath 'C:\Work\M2 Portable'
py -3.11 -m venv 'C:\Work\M2 Runtime\.venv'
$M2Python = 'C:\Work\M2 Runtime\.venv\Scripts\python.exe'
& $M2Python -m pip install -r '.\requirements.txt'
& $M2Python -I -B '.\m2.py'
& $M2Python -I -B '.\m2.py' doctor
```

`py -3.11` 适用于已安装 Python 3.11 的机器；已有其他 3.11+ 解释器时，用它的完整路径创建虚拟环境。PowerShell 中含空格的可执行文件路径前需要 `&`。

macOS/Linux shell：

```sh
cd '/absolute/path/M2 Portable'
python3 --version
python3 -m venv '/absolute/path/M2 Runtime/.venv'
M2_PYTHON='/absolute/path/M2 Runtime/.venv/bin/python'
"$M2_PYTHON" -m pip install -r './requirements.txt'
"$M2_PYTHON" -I -B './m2.py'
"$M2_PYTHON" -I -B './m2.py' doctor
```

这些是对应 shell 的路径写法，不代表已经完成 macOS/Linux 实机验收。实际覆盖以本次交付验证记录为准；迁移机器后应重新运行 `doctor`。安装依赖需要包源可达；离线环境由操作者提供与平台匹配、来源可信的依赖包。

`-I` 使用 Python 隔离模式，`-B` 避免写入字节码缓存。若 `doctor` 拒绝继续，先按输出原因处理；不要删除校验逻辑或修改清单以掩盖问题。

## 2. 先让 AI 了解项目

准备一个包外项目目录，例如 `C:\Work\Example Project`。其中先有你要提供的真实资料，再为资料逐项建立索引；不要求创建下面示例中的全部文件。

Windows PowerShell，沿用上一步的 `$M2Python`：

```powershell
& $M2Python -I -B '.\m2.py' project-init `
  --root 'C:\Work\Example Project' `
  --config 'C:\Work\M2 Runtime\project.json' `
  --project-id 'example-project' `
  --goal '核对需求与实现，列出证据充分的问题，确认范围后再施工' `
  --source 'requirements=docs/requirements.md' `
  --source 'code=src/main.py' `
  --source 'tests=tests/test_main.py' `
  --source 'memory=docs/project-memory.md'

& $M2Python -I -B '.\m2.py' start --project 'C:\Work\M2 Runtime\project.json'
```

macOS/Linux，沿用上一步的 `$M2_PYTHON`：

```sh
"$M2_PYTHON" -I -B './m2.py' project-init \
  --root '/absolute/path/Example Project' \
  --config '/absolute/path/M2 Runtime/project.json' \
  --project-id 'example-project' \
  --goal '核对需求与实现，列出证据充分的问题，确认范围后再施工' \
  --source 'requirements=docs/requirements.md' \
  --source 'code=src/main.py' \
  --source 'tests=tests/test_main.py' \
  --source 'memory=docs/project-memory.md'

"$M2_PYTHON" -I -B './m2.py' start --project '/absolute/path/M2 Runtime/project.json'
```

把不存在或不想提供的示例来源删除，并换成真实文件。来源使用项目根内的相对文件路径，可重复传入 `--source`；不使用目录、通配符或自动扫描。八类来源及缺失、冲突、过期信息的填写方式见 [PROJECT_CONTEXT.md](docs/PROJECT_CONTEXT.md)。配置目标必须是新文件。

没有配置时可运行 `start` 查看启动检查与后续步骤，但这并不表示工具已经理解了你的项目。`project-init` 仅生成索引，不生成可信授权，不创建治理账本，也不验证项目需求已经满足。

## 3. 查看接入步骤

```powershell
& $M2Python -I -B '.\m2.py' workflow
```

macOS/Linux：

```sh
"$M2_PYTHON" -I -B './m2.py' workflow
```

接下来按 [WORKFLOW.md](docs/WORKFLOW.md) 准备当前任务的可信配置与外部签署资料。

**已有配置**才运行下面命令。固定哈希由可信操作者提前审核并另行保存，不要在调用时从请求可修改的文件临时计算：

```powershell
& $M2Python -I -B '.\m2.py' readiness `
  --config 'C:\Work\M2 Control\trusted-bootstrap.json' `
  --config-sha256 '<事先审核保存的64位小写SHA256>'
```

macOS/Linux：

```sh
"$M2_PYTHON" -I -B './m2.py' readiness \
  --config '/absolute/path/M2 Control/trusted-bootstrap.json' \
  --config-sha256 '<事先审核保存的64位小写SHA256>'
```

`readiness` 只检查配置及 pin，辨认 CONFIG_1/2/3，不创建账本、不签发身份或 Scope、不执行独审或验收。你没有这些可信资料时，当前可完成环境检查和项目知识准备；完整治理任务尚未装配。

## 4. 可选：运行一次隔离样例

```powershell
& $M2Python -I -B '.\m2.py' sample --output 'C:\Work\M2 Sample 01'
```

```sh
"$M2_PYTHON" -I -B './m2.py' sample --output '/absolute/path/M2 Sample 01'
```

输出必须是包外、绝对、全新且无符号链接的目录。样例执行原 `flow01` 失败经验复用流程，在隔离环境使用 `TEST_ONLY` 临时身份与当前样例授权；原失败回执会保留，后续读取产生参考上下文。样例内的预期失败不应被改写为成功。

样例完成只证明本次样例覆盖的行为，不代表你的项目已经测试、独审或通过验收。第二次运行使用另一个新目录，保留第一次输出。真实项目应使用自己的范围、身份、预算和持续账本，不能照抄样例的临时授权。

## 给接手 AI 的一句话

> 请先读包根 AGENTS.md，用包外 Python 环境运行 m2.py doctor，再用我提供的 project.json 运行 start。把来源缺失、冲突、旧报告和未验证的事实列清楚。按 docs/WORKFLOW.md 识别当前配置与授权；在具备相应授权及证据前，不把启动、TEST 或样例成功报告为项目 PASS。
