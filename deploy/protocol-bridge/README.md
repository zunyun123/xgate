# y-gate → Hysteria2 / TUIC 协议桥

本目录提供一个**独立 sing-box 侧车**，把 Hysteria2/TUIC 客户端入站流量经 y-gate 的认证 SOCKS5 出口转发。它不修改 y-gate 面板数据库，也不把 HY2/TUIC 入口纳入 y-gate 的逐客户端绑定、订阅转换或节点 CRUD；这是对现有项目的低风险旁路扩展，不是面板内置协议实现。若需要面板中原生创建/管理 HY2/TUIC，应另行扩展入口数据模型、协议路由、客户端管理和订阅系统。

## 前提条件

- y-gate 在同一台 Linux 主机上运行，并已连接可用出口。
- 从 y-gate UI 获取一个**认证 SOCKS5** 地址，确认仅本机或受控网络可访问。不要猜测固定端口：y-gate 配置的实际端口和凭据可能不同。HTTP 代理地址不能填在此处。
- 主机有客户端可访问的公网地址/域名、可被系统验证的 TLS 证书（SAN 应匹配 `--host`）、Docker Compose。
- 防火墙和云安全组允许选定的 UDP 入站端口。

## 配置并启动

将此目录复制到 y-gate 所在 VPS，进入 `deploy/protocol-bridge`。在 `certs/` 放好 `fullchain.pem`、`privkey.pem`，证书路径会挂载到容器的 `/etc/sing-box/certs/`。使用 y-gate 显示的 SOCKS5 地址生成配置：

```bash
python3 generate_config.py \
  --host proxy.example.com \
  --upstream 'socks5://USER:PASSWORD@127.0.0.1:SOCKS_PORT' \
  --output config.json
```

将示例凭据、端口和域名替换为实际值。URL 中密码若含 `@`、`:`、`%` 等字符，先做 URL 百分号编码；生成器会解析并解码认证字段。不要把真实口令写入仓库、公开日志或分享给无关人员。也可以设置 `PROXY_PASSWORD` 和 `PROXY_UUID` 环境变量指定客户端凭据；默认生成随机凭据。

启动服务：

```bash
mkdir -p certs
# 将证书及私钥放入 certs/，然后：
docker compose up -d
```

默认监听 `8443/udp` (Hysteria2) 和 `8444/udp` (TUIC)。在云安全组与主机防火墙开放这两个 UDP 端口；证书续期后重启容器。若使用 IPv4-only 主机，确认 sing-box 的 `listen: ::` 在系统上也接受 IPv4，或将配置中两个入站的 `listen` 改为 `0.0.0.0`。

生成器会输出可导入客户端的两种节点链接。链接、`config.json` 均含认证凭据，应按秘密资料保管。TLS 校验保持开启；不要通过禁用校验规避证书错误。

## 串联方向与限制

```text
客户端 --UDP/Hysteria2 或 TUIC--> sing-box 侧车 --SOCKS5--> y-gate 代理出口 --> 当前选定的出口节点
```

- 侧车只转发到传入 `--upstream` 的 SOCKS5 地址。确认该地址会经过预期的 y-gate 出口；侧车不会读取或自动跟随 y-gate 的出口切换状态。
- SOCKS5 TCP CONNECT 通常能转发 TCP 请求；UDP ASSOCIATE 是否可用取决于 y-gate 该代理监听器及其上游支持。客户端到侧车使用 QUIC/UDP，不代表 SOCKS 上游支持 UDP 转发。需实际测试 UDP 应用；不支持时可能只有部分流量可用。
- 若 y-gate 的代理凭据或端口变化，需重生成配置并重启侧车。
- 此桥需要 VPS 上有可公网访问的 UDP 入口；没有公网 IP 时，局域网可做本机/局域网验证，但公网用户需要能承载 UDP 的隧道/中继。普通 HTTP 反代或 Cloudflare Workers/Pages 不会自动提供该 UDP 服务。
- `network_mode: host` 是为让侧车访问本机回环 SOCKS5；请保证上游只绑定本机/受控接口，避免开放未认证代理。
