# IP 地址分配器（DHCP 服务器）- V1.01

一款轻量级 Windows 图形界面工具，可监听所选网络接口上的 DHCP 报文，并使用一个固定 IP 地址（默认 `192.168.1.20`）响应 DHCP **Discover / Request** 请求。程序使用 Python、**Scapy** 和 **PyQt5** 编写，可打包为单文件可执行程序。

版本：**V1.01**（按 RFC 广播标志自适应回应；首个公开版本为 V1.00）

## 功能

- 列出具有 IPv4 地址的可用网络接口
- 配置要分配的 IP 地址
- 收到 DHCP **Discover** 时发送 **Offer**，收到 **Request** 时发送 **ACK**
- 为成功分配的地址记录带时间戳的日志
- 可随时启动或停止；报文捕获和发送在后台线程中运行
- 简体中文界面，无控制台窗口，无需安装程序

## 下载

请从 [GitHub Releases](https://github.com/hq8231516/DHCP_SERVER/releases/tag/V1.01) 页面下载 `DHCP_Server_V1.01.exe`。仓库仅包含源代码和文档。

## 运行要求

| 项目 | 说明 |
| --- | --- |
| 操作系统 | Windows 10 / 11，64 位 |
| Npcap | Scapy 捕获报文和发送原始以太网帧所必需。请安装 [Npcap](https://npcap.com/)，并启用与 WinPcap 兼容的 API 模式。 |
| 权限 | 普通用户权限即可运行，不弹出 UAC 提示。若 Npcap 安装时启用了"仅管理员可访问驱动"（`AdminOnly=1`），则需右键选择"以管理员身份运行"。 |
| 网络 | 所选网卡需要配置与待分配 IP 地址位于同一子网的静态 IPv4 地址；该网段不应同时运行其他 DHCP 服务器。 |
| 防火墙 | 不得阻止 UDP 端口 67 / 68。 |

> 这是面向工作台和实验室场景的轻量级地址分配工具，并非完整的 DHCP 服务器。
> 它不维护租约数据库、不响应 NAK / Release / Inform，并且始终向每个客户端分配相同的 IP 地址。

## 使用方法

1. 运行 `DHCP_Server_V1.01.exe`（无需 UAC 提权；若本机 Npcap 限制了管理员访问，请右键"以管理员身份运行"）。
2. 选择连接到待测设备的**网络接口**。
3. 在**分配 IP**中设置要分配的地址（默认值为 `192.168.1.20`）。
4. 点击**开始**。日志会显示类似 `已在 <接口>（<服务器 IP>）启动，分配地址：<IP>` 的信息。
5. 启动或重启客户端设备。客户端请求地址后，日志会显示类似 `已分配：MAC=xx:xx:xx:xx:xx:xx -> IP=192.168.1.20` 的信息。
6. 完成后点击**停止**或关闭窗口。日志会显示“已停止”。

## 工作原理

```
客户端                    IP 地址分配器
  |--- DHCP Discover --->|
  |<---- DHCP Offer -----|  yiaddr = 配置的 IP，server_id = 网卡 IP
  |--- DHCP Request ---->|
  |<----- DHCP ACK ------|  租约 1 天，掩码 255.255.255.0，路由器 = 0.0.0.0
```

程序通过 `sniff(filter="udp and (port 67 or port 68)")` 捕获报文，并使用 `sendp()` 在二层发送构造的响应报文。回包方式按 RFC 2131 根据客户端 BOOTP 广播标志（0x8000）判断：置位时 Offer / ACK 发往二层 + 三层广播（目的 MAC `ff:ff:ff:ff:ff:ff`，目的 IP `255.255.255.255`）；未置位时单播给客户端硬件地址 `chaddr` 和分配地址 `yiaddr`。两种情况下均原样回显客户端的 flags 值；参考抓包中的客户端设置了广播位，因此实际交互走广播路径。报文字段与 DHCP SERVER 2.52 的参考抓包对齐，租约 1 天、NetBIOS 节点类型 H-node（8）。专用的发送线程负责处理发送队列，避免阻塞报文捕获回调。

回归对比：仓库根目录的 `DHCP.pcapng` 是参考抓包，运行 `python regression_check.py` 可将本程序生成的 Offer / ACK 与抓包中的真实响应逐字段比对，并验证广播标志置位（0x8000 → 广播）和清零（0x0000 → 单播）两个分支（应全部为 PASS）。

## 从源代码构建

```bash
pip install scapy==2.7.0 PyQt5==5.15.2 pyinstaller==6.19.0

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name DHCP_Server_V1.01 --collect-all scapy dhcp_server.py
```

可执行程序将生成在 `dist/` 目录中。程序不会捆绑 Npcap，目标计算机必须自行安装。

## 故障排除

- **网络接口列表为空** - 请确认已安装 Npcap、网卡具有有效的 IPv4 地址（不是 APIPA 地址或回环地址）；若 Npcap 启用了管理员访问限制，请右键"以管理员身份运行"。
- **无法获取网络接口的 MAC 地址** - 请通过 `ipconfig /all` 检查网卡，并尝试选择其他接口。
- **客户端未获取到 IP 地址** - 检查网线和链路、子网、本机防火墙是否放行 UDP 端口 67 / 68，以及同一网段是否存在其他 DHCP 服务器。
- **杀毒软件提示可执行文件存在风险** - PyInstaller 单文件程序常会被误报。如需验证，可从源代码自行构建。
- **普通权限下无法抓包或发送报文** - 本机 Npcap 可能启用了"Restrict Npcap driver's access to Administrators only"。右键以管理员身份运行即可；也可重新安装 Npcap 并保持该选项不勾选（默认状态）。

## 文件

| 文件 | 说明 |
| --- | --- |
| `dhcp_server.py` | 应用程序源代码（简体中文界面，V1.01） |
| `DHCP.pcapng` | DHCP SERVER 2.52 参考抓包（Discover×5 / Offer / Request / ACK） |
| `regression_check.py` | 基于参考抓包的报文回归对比脚本 |
| `README.md` | 本文档 |
| `.gitignore` | 排除构建产物和本地状态文件 |

## 许可证

此版本未指定许可证。
