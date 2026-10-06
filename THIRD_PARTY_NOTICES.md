# 来源与第三方依赖声明

本仓库的自定义学习研究许可只覆盖相应权利人可许可的材料；不改变第三方组件本来的权利和许可。依赖安装时应保留其随附版权与许可证。

| 组件 | 用途 | 许可 / 来源 |
|---|---|---|
| Python 3.11+ | 解释器与标准库，不随包分发 | [Python 许可](https://docs.python.org/3/license.html) |
| cryptography >=41 | Ed25519 等密码接口；外部安装，不随包分发 | 已核对的 46.0.3 元数据为 Apache-2.0 OR BSD-3-Clause；[该版本 LICENSE](https://github.com/pyca/cryptography/blob/46.0.3/LICENSE) |
| pytest >=7 | 可选开发测试依赖，不是普通启动依赖 | [pytest 源码与许可](https://github.com/pytest-dev/pytest) |
| setuptools >=68 | 原内核包的构建依赖，非便携入口常规启动必需 | [setuptools 源码与许可](https://github.com/pypa/setuptools) |

此表说明直接依赖，不是所有未来安装版本及其传递依赖的完整软件物料清单。具体离线安装包、wheel、环境或容器如另行分发，应按实际内容补充声明。本发行候选没有 vendored 依赖源码、第三方 wheel 或模型权重。

C06 设计和源码思路的出处见 [来源说明](docs/PROVENANCE.md) 及固定包原记录。这里不把“能够访问源码”视为第三方许可授权，也不以本项目许可证重新许可第三方内容。

新图件以项目文字和代码生成，无外部品牌图标或用户截图。商标及服务名称属于相应权利人，引用不表示其背书。
