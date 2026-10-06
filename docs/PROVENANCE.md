# 固定来源与公开派生范围

社区候选版本：**M2-RESEARCH-20261006-RC1**。此版本整理研究文档、图件、许可和公开方法说明，不增加运行能力。

| 来源 | 身份与边界 |
|---|---|
| 固定施工内核 | CK-FINAL-20260928-01；原始 ZIP SHA256 `e34f84ecca424115c1bcdb2df37e63e0c0c2d029c52662d1cb8b594e8a0b194f`；历史人工接受限原版本 |
| 便携父包 | M2-Construction-Portable-20261004；53 个成员原字节嵌入 |
| 直接发布输入 | M2-Construction-Portable-Start-20261006-R2.zip；SHA256 `27e79450a8aa5af4c791a38f41846740569c165d62ce33c0a448999c032e8c56` |
| 当前公开副本 | `runtime/` 共 74 个文件；70 个与直接输入相同，所有 Python 源码及 53 个父包文件相同 |

公开副本的四处差异是 `methods/README.md`、`methods/CONSTRUCTION_ACCEPTANCE_V2.md`、`methods/acceptance-rules-v2.json` 和相应 `WRAPPER_FILES.json`。前三项删除项目内部安排并改为研究参考；后一项记录新参考文件的实际字节。研究规则里的 CK01–CK13、LC01、FE01 断言与证据列表保持。详细前后哈希见 [RUNTIME_PROVENANCE.json](../RUNTIME_PROVENANCE.json)。

外层 README、图件、配置及研究文档是本次新增。原来的 `runtime/PORTABLE_VALIDATION.json` 仍是历史验证记录，没有改成新研究版本的验收结果。旧记录中的 R1/R2 和内部证据哈希按原含义理解；仅有哈希并不使未公开的原始日志成为可供外界独立核验的证据。

## 与 C06 的关系

施工版参考 C06 的数据约束、信任绑定、日志与文件写入思路，重新实现和适配成独立 Python 工程。它不在运行时加载 C06，公开仓库没有 C06 产品源码、配置、私钥或商业数据。

保留 [原来源说明](../runtime/baseline/M2-Construction-Portable-20261004/core/docs/PROVENANCE.md) 中的逻辑文件名与固定哈希，用于出处追溯。其中“公开源码”“公开发布包”是历史材料的名称和描述，**不构成 C06 已有开源许可证的证明**。本次施工版许可不扩大到 C06 整体。

## 权利与依赖

发布署名和许可权利人按维护者提供的信息记为 yyf；哈希只说明字节身份，不证明法律权属。第三方依赖仍用各自许可证，见 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。当前仓库不打包模型权重、Python 解释器或依赖库二进制。

## 怎样引用

建议写明：yyf，M2 Construction Governance，所使用的确切版本或 Git 提交，以及取得材料的仓库地址。没有 DOI 或已发表论文时不要补写；对本文方法的复现结论应附自己的环境和实际证据。
