# 独立 TEST_ONLY 样例

先按包根 README.md 安装 Python 依赖，再在包根运行：

```powershell
$sampleOut = Join-Path (Split-Path (Get-Location).Path -Parent) ('construction-sample-' + [guid]::NewGuid().ToString('N'))
python -B ./tools/run_failure_sample.py --output "$sampleOut"
```

请使用安装了 cryptography 的解释器；主 README 的 `$python` 可替代此处 `python`。输出必须是全新、包外、规范绝对路径且不得含链接。本入口仅执行既有 flow01，无需 pytest，无模型、数据库或网络服务。

已有测试夹具会新建独立 TEST_ONLY Ed25519 身份：私钥只在进程内存，公开 pin、当前 CLI 配置与签名范围写到此次输出的 supervisor/state 目录，绝不使用原机器身份。旧回执不重放。

预期：先保留命令退出 7 的 FAILED 回执（桥返回 2），再以当前新任务/新授权生成 ADVISORY_ONLY 上下文；入口最终退出 0。`flow01/flow-result.json` 记录 `original_command_status=FAILED`、`original_command_exit=7`、`dispatch_allowed=false`。它不把原失败改为成功，也不构成人工 PASS。

flow02 和 flow03 的测试源码保留，本次不为打包重复执行；不宣称它们已在此派生包重验。源码中的历史 `--baseline-red` 与 R3 对照测试需要原 ZIP 未包含的旧快照，属于仅审阅部分；不可用当前桥冒充旧桥。详见主 README 的限制。
