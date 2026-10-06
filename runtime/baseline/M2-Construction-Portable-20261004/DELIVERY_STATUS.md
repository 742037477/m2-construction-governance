# 施工版便携派生交付边界

版本：CK-FINAL-20260928-01-portable-20261004。

可信来源、原 ZIP 哈希及逐文件改动见 SOURCE_BASELINE.json 与 CHANGELOG_PORTABLE.md。原 CK-FINAL-20260928-01 在 2026-09-28 获人工 PASS 并暂停；该事实不授予当前执行权限，本次便携派生未获新人工验收。

CORE_CAPTURE.json 与 DELIVERY_MEMBERS.json 是本次派生的字节清单，不是原签名、生产 Root、执行授权或独立审计。BASELINE.json 只保留历史出处的逻辑名及原哈希。旧部署配置、身份、授权、私钥、日志和历史会话均未随包提供。

核心运行时代码、桥及失败经验模块保持来源字节。33 个核心成员的完整性核验与签名 Gate 保留；路径相关文档/测试修改已重新固定派生哈希。样例通过已有 make_real_case / signed_scope 生成新的 TEST_ONLY 内存身份、当前范围和签名。

从 README.md 开始。该 Python 框架只治理接入它的登记入口，不是全局 Codex 工具拦截器、操作系统沙箱、网页平台或独立 exe。C06 服务与生产接入均不在本包授权和验证范围内。
