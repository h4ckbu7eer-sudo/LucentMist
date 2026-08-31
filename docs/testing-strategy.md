# 回归测试与真实外部验证策略

2026-08-31 决策：使用本地生成证书，**不靠排除测试维持 CI 绿色**。

## 统一门禁

- Windows/Ubuntu 主 CI、hourly 自检、`scripts/check.*`、`scripts/auto-check.*` 和发布构建脚本都执行完整 `dotnet test -c Release` 套件。
- 主 CI 已移除 `Category!=External` 过滤。当前 8 个带 External 标签的百度 TLS 测试全部替换，无 External 测试继续依赖 baidu.com。
- 自动化回归的断言必须由测试控制：本地数据、假 HTTP handler，或有时限的 loopback 真实 TCP/TLS 服务。不得根据外站当时的证书内容、证书链长度、访问是否成功决定发布是否合格。
- 真实 DeepSeek/云 CVE API/网关验证仍使用显式 opt-in 的 `scripts/validate-deepseek.py` 等脚本，保存真实失败和环境边界；它们不属于默认 xUnit 回归。网络被阻断、key 撤销或第三方限流应记录，不能伪造成产品回归通过。

## 原 8 个外网 SSL 测试的替代

| 原覆盖 | 现在如何验证 |
| --- | --- |
| 连接 baidu.com:443 成功 | 127.0.0.1 随机空闲端口，真实 TLS 握手成功 |
| 结果字段完整 | 本地证书结果逐字段断言 |
| subject/issuer/日期/thumbprint | 已生成的 CN、非空 issuer、有效期、SHA-1/SHA-256 字段 |
| SAN 含 baidu 字样 | 精确断言 `validation.invalid`、`127.0.0.1`、`::1`，不依赖格式化语言 |
| 外站证书链通常有 2 个以上 | 已知自签链恰好一个元素，thumbprint 与叶证书一致；不再假设外站链拓扑 |
| baidu.com:80 不是 TLS | loopback 服务写入固定明文 HTTP 响应，断言 TLS 失败 |
| 未过期证书剩余天数 | 本地生成 30 天有效证书，断言未过期、剩余 29–30 天 |
| 默认端口 443 | 直接断言生产 endpoint 归一化的默认端口，不抢占宿主机 443 |

证书不安装到系统/用户信任库，没有 AIA/CRL 网络地址；自签不受信、名称不匹配、过期等原有本地用例继续执行。监听端口由 OS 分配，accept/握手均有取消期限，结束关闭监听器并等待服务任务。非法目标测试也在格式校验阶段拒绝，不再查询公共 DNS 的 `.invalid` 名称。

本地新 SAN 用例在修改生产解析器前真实失败：IPv6 被显示字符串解析成 `0000:0000:0000:0000:0000:0000:0000:0001`，预期规范形式 `::1`。原代码还依赖 `DNS Name=` 等系统格式标签。现使用 .NET `X509SubjectAlternativeNameExtension` 读取 DER 中 DNS/IP SAN，避免系统语言/格式差异；不是修改断言迎合错误输出。

这消除了上述八项的外网不确定性，不等于“所有测试永不 flaky”。本机资源耗尽、平台加密库问题仍可能导致真实失败，应保留日志调查。多级受信 CA/撤销服务器的完整场景未由这八项覆盖，不能把自签单节点测试宣称为全 PKI 验证。
