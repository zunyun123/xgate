# Hysteria2 / TUIC 串联输出

> 目标：订阅里只出现 Hysteria2 / TUIC 节点，流量最终仍走家宽出口。
> 做法不是给 miku-gate 换一套拨号逻辑，而是复用它已有的 sing-box
> 核心做“协议转换层”，再串联已有的 SOCKS5 出口。

## 链路

```text
客户端 --Hysteria2/TUIC (UDP/QUIC, TLS)--> 本机 sing-box 入站
        --SOCKS5--> 127.0.0.1:8500（默认串联上游）
                    └─ AimiliVPN 式本地出口：它继续负责 VPN Gate 拨号与家宽通道
        --或--> 绑定的 miku-gate 隧道 SOCKS（入站绑了具体出口时）
```

miku-gate 原生没有 Hysteria2/TUIC 服务端，Xray 入站也没有这两个协议，
所以这两个协议**只能在自建 sing-box 模式下创建**。在 Xray、3x-ui、
S-UI 模式下创建会直接报错，不会生成一份跑不起来的配置。

## 怎么建

1. 面板模式切到“自建 sing-box”（不是 Xray，不是 3x-ui/S-UI）。
2. 新建节点，协议选 Hysteria2 或 TUIC。
   - 传输自动锁死 UDP，安全自动锁死 TLS，不能改成 ws/grpc/REALITY/none。
   - TLS 域名与证书走和 VLESS 一样的流程：优先用已绑定域名证书，
     没域名时生成自签证书，分享链接里自签用 `insecure=1` /
     `allow_insecure=1`，正式证书则正常验签。
   - 端口建议：Hysteria2 用 8443，TUIC 用 8444，两个都是 UDP，
     不能和已有入站撞端口，也不能撞 8500。
3. 出口选择：
   - **不绑出口**：默认走串联上游 `127.0.0.1:8500`。这要求同一台
     机器上确实有 AimiliVPN（或任何在 8500 提供 SOCKS5 的程序）
     在跑；8500 没起来时 Hy2/TUIC 节点能连上握手、但流量出不去。
   - **绑了出口**：走该出口的 miku-gate 隧道 SOCKS，不走 8500。
     这是“只输出 Hy2/TUIC、但用 miku-gate 自己的出口”的用法。
4. 订阅里会出现 `hysteria2://…` / `tuic://…` 链接。
   通用（Base64）、明文、Clash、sing-box 四种订阅格式都已适配，
   不会因为多了这两种协议就让整个订阅转换失败。

## 改串联上游

默认 `127.0.0.1:8500`，不用改代码。起服务前设环境变量即可
（Docker 部署写进 `.env`，原生部署写进服务环境）：

```dotenv
MIKU_RELAY_UPSTREAM=127.0.0.1:8500
# 上游要用户名口令认证时才填，无认证留空
MIKU_RELAY_UPSTREAM_USER=
MIKU_RELAY_UPSTREAM_PASS=
```

改完环境变量要重启后端并重新生成一次入站配置（改任一入站或
重启服务都会触发 `apply` 重建 sing-box 配置），只改 `.env` 不重启
不会生效。

## 独立串联（不用 miku-gate 面板时）

如果只想在已装 AimiliVPN 的机器上单独起一个转换层，不用改
miku-gate，sing-box 配置的核心就是下面这三段，其他字段按
自己的证书和密码填：

```json
{
  "inbounds": [
    {"type": "hysteria2", "listen": "0.0.0.0", "listen_port": 8443,
     "users": [{"password": "换成自己的密码"}],
     "tls": {"enabled": true, "server_name": "example.com",
             "certificate_path": "/path/to/cert.crt", "key_path": "/path/to/cert.key"}},
    {"type": "tuic", "listen": "0.0.0.0", "listen_port": 8444,
     "users": [{"uuid": "换成自己的 UUID", "password": "换成自己的密码"}],
     "congestion_control": "bbr",
     "tls": {"enabled": true, "server_name": "example.com",
             "certificate_path": "/path/to/cert.crt", "key_path": "/path/to/cert.key"}}
  ],
  "outbounds": [
    {"type": "socks", "tag": "relay-upstream", "server": "127.0.0.1",
     "server_port": 8500, "version": "5"},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"rules": [
    {"inbound": ["in-8443-udp", "in-8444-udp"], "action": "route", "outbound": "relay-upstream"}
  ], "final": "direct"}
}
```

## 已知限制，部署前先看

- **UDP 要看上游脸色**：Hy2/TUIC 客户端的 UDP 流量经 SOCKS5
  转发时依赖上游支持 UDP ASSOCIATE；如果 8500 那边只支持 TCP
  CONNECT，TCP 网站能开、UDP/QUIC 类应用会不通，这是串联架构
  本身的限制，不是入站配错了。
- **没有逐客户端分流**：Hy2 用户只有密码、TUIC 用户没有 name
  字段，做不了 VLESS 那种按 `auth_user` 的逐客户端路由。
  串联入站只认入站级绑定，一个入站只能走一个出口。
- **防火墙要放行 UDP**：Hy2/TUIC 端口是 UDP，不是 TCP，
  云安全组和系统防火墙都要放 UDP，否则客户端连握手都到不了。
- **自签证书的取舍**：自签时链接带 `insecure`，等于放弃了
  对服务端的证书校验，换正式证书后应去掉这一项。
- **8500 本身不是 miku-gate 的**：miku-gate 自己的隧道是每条
  出口一个独立 SOCKS 端口，不存在统一的 8500；8500 是
  AimiliVPN 侧的约定，两边要装在同一台机器上串联才成立。
