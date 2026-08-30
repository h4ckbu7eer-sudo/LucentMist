# 本机主接口一致性验证

日期：2026-08-31（Asia/Shanghai）。本次修复针对 `get_my_ip` 与 CLI/API 提示词选出不同主 IP 的矛盾。

## 单一判定来源

工具与提示词均调用 Core 的 `LocalNetworkInfo.GetPrimaryInterface`。CLI/API 不再各自组装未经主次标注的网卡列表，而是调用同一个 `InjectLocalNetworkInfo`。

选择规则：

1. 只使用活动、可用的非回环 IPv4 地址。
2. 排除已识别虚拟、隧道和回环接口；Windows 使用接口类型、名称及描述，Linux 另外读取 `/sys/class/net` 链接是否指向虚拟设备路径。
3. 优先选择有有效 IPv4 网关的非虚拟以太网/WLAN 接口。
4. 没有网关时回退到非虚拟私网接口；没有合适接口时 `primaryIp` 和顶层 `suggestedSubnet` 为 null，不自动选择虚拟网络。
5. 同级候选按名称/IP 稳定排序，结果不依赖系统枚举顺序。

工具保留活动接口清单，并增加 `isVirtual`、`isPrimary` 和 `interfaceType`。CLI 主 IPv4 高亮；其他接口注明“虚拟（非主接口）”或“其他接口（非主接口）”。提示词仅突出主接口并附虚拟网卡数量。

## 真实 Windows 本机验证

使用临时 .NET 调用程序分别运行生产 `GetMyIpTool.ExecuteAsync`（默认构造）与共享网络信息/提示词函数。它们独立枚举本机网卡，不调用外部 IP 服务，不使用模型或伪造网卡数据。

实际顺序及结果：

| 枚举顺序 | 接口 | IPv4 | 虚拟 | 主接口 |
| --- | --- | --- | --- | --- |
| 1 | VMware Network Adapter VMnet8 | 192.168.12.1 | true | false |
| 2 | WLAN 2 | 192.168.99.9 | false | true |
| 3 | vEthernet (WSL (Hyper-V firewall)) | 172.17.80.1 | true | false |

工具输出摘录：

```json
{
  "primaryIp": "192.168.99.9",
  "primaryInterface": "WLAN 2",
  "gateway": "192.168.99.1",
  "suggestedSubnet": "192.168.99.0/24",
  "virtualInterfaceCount": 2
}
```

提示词输出摘录：

```text
主接口: WLAN 2；主 IPv4: 192.168.99.9/24；网关: 192.168.99.1；另有 2 个虚拟网卡（非主接口）
INDEPENDENT_ENUMERATIONS_PRIMARY_MATCH=true
```

## 自动化验证

- VMnet8/vEthernet 排在前面，以及工具和提示词使用相反枚举顺序，均选中 WLAN。
- 覆盖 Windows 虚拟描述、Linux docker/veth/bridge/tun/wg、Linux sysfs 虚拟标记。
- 覆盖多物理接口顺序变化、有网关优先、无网关回退、只有虚拟网卡和无可用网卡。
- 渲染测试验证虚拟标签；Agent 确定性摘要测试验证只突出 `primaryIp`，不并列列出虚拟 IP。
- Release 构建：0 警告、0 错误。
- 全量测试：437/437（Tools 314、Agent 66、Scanning 31、API 26）。

## 诚实边界

- 本机 Windows 的两条数据来源已真实验证；Linux 选择规则由构造元数据测试覆盖，不冒称本次在真实 Linux 主机运行过。
- 当前运行环境未配置 `LMIST_LLM_APIKEY`，本次没有真实 DeepSeek 对话记录。共享数据来源、渲染、确定性摘要已验证；模型是否遵守简洁回答规则仍需实际模型复测。
- “主接口”是统一的物理网络候选选择策略，不等于目标专属路由或公网出口 IP。多网关时不读取 OS 路由 metric。
- 虚拟识别基于系统信息及名称/描述规则，并非硬件证明；重命名或未暴露虚拟标识的设备仍可能无法识别。
- 提示词保持 `LMIST_INJECT_NETWORK_INFO=true` 才注入的隐私边界。网卡/DHCP 在会话中发生变化时，以最新工具结果为准并说明变化，不把启动快照视作永久事实。
