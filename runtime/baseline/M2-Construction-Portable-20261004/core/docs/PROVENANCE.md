# 便携派生说明

此文的来源核验为原交付历史记录；本次只将本机出处改为逻辑包名，未读取或重签 C06。法律/来源归属不变，未新增开源授权。

# CK-20260927-GM-01：C06 公开源码来源

本候选的设计参考固定的 C06 公开发布包：

`BEV2-ERP-Assistant-Local-20260924-G0-C06.zip (logical upstream artifact name)`

发布包 SHA-256：`e35d3129d1a7ad5c76db079bfe5ec0af44f38a5b7feb697a1cf11e4342afbe7c`。

以下 SHA-256 是该 ZIP 内对应成员的**解压后原始字节**哈希；本次用只读方式重新计算，发布包与四个成员均与固定值一致。

| ZIP 内路径 | SHA-256 |
| --- | --- |
| `deployment/kernel/src/yingqi_m2_r2/contracts.py` | `4afdc23299ac4ed276e72d585d62c30b5ca769a4f0feb7f21cc9097e4bf67842` |
| `deployment/src/business_v2/trust_binding.py` | `0b9be6bce6ae9bf1aa8897a294549e92472b9c1e19e449b31eda12a45210df70` |
| `deployment/kernel/src/yingqi_m2_r2/journal.py` | `495ec624cec9f44874f0453d8c437c0f6189e3ab8bf5c4ba8b1ead8abf5c858f` |
| `deployment/kernel/src/yingqi_m2_r2/product_io.py` | `aade2656102baa5f05b68a1a87e7a8500f51d83160fb3786010a3cba48f8ebce` |

本候选重新实现并适配其中的数据约束、信任绑定、日志与文件写入思路，以满足本任务的接口和边界。它不在运行时导入、解压或调用 C06 包，也不依赖 C06 的私钥；C06 私钥和私有状态不属于本候选的输入或交付物。本次来源核验只读取了发布包哈希及上表四个源码成员，没有读取密钥。

## 规范化 JSON 版本选择

C06 包内存在两个不同的规则，不能混用。本候选为签名及哈希输入明确选择 `trust_binding.py` 中的 BEV2 规则 `BEV2_JSON_SORTKEYS_UTF8_1`：对象键按 Python `sort_keys=True` 的 Unicode 码点顺序排序，`ensure_ascii=False`，紧凑分隔符 `(',', ':')`，输出 UTF-8 字节；仅接受 `null`、布尔值、字符串、列表、字符串键对象和 **0 至 2^53-1** 的整数，不接受浮点数或非有限数。与之不同，`contracts.py` 的较早规则按 UTF-16 码元排序对象键，并允许绝对值不超过 `2^53-1` 的负整数。两者在部分键及整数输入上会产生不同结果，故较早规则不作为本候选的签名/哈希规范化依据。
