# Hysteria2 / TUIC 输出（sing-box 后端）

## 一句话

y-gate 本来就用 sing-box 把 VPN Gate 家宽出口转成 VLESS/Trojan，
本次把 Hysteria2 和 TUIC 也接进同一条链路（VMess 已移除，见下）：

```text
客户端 --(Hy2/TUIC, UDP/QUIC, TLS)--> y-gate 的 sing-box 入站
        --(路由规则，按绑定出口)--> 该出口隧道的 SOCKS5（127.0.0.1:隧道端口）
        --(OpenVPN, netns)--> VPN Gate 家宽出口 --> 互联网
```

这正是你说的 AimiliVPN 思路，只不过 y-gate 不需要再另起一个 sing-box，
也不需要一个共用的 `8500` 端口：

| | AimiliVPN 的做法 | y-gate 本次的做法 |
| --- | --- | --- |
| 底层出口 | OpenVPN / SoftEther 维护 VPN Gate 连接 | OpenVPN 隧道（netns 隔离），每条出口一个 |
| 内部代理出口 | 统一输出到本地 `8500`（HTTP/SOCKS5） | 每条出口一个本地 SOCKS5 端口（`tunnel.Port`，带凭据），sing-box 出站直接连 `127.0.0.1:隧道端口` |
| 协议转换 | 另起 sing-box，入站 Hy2/TUIC，出站指向 `8500` | y-gate 自带的 sing-box 就是转换器，入站 Hy2/TUIC，出站按绑定走对应隧道的 SOCKS5 |
| 只输出 Hy2/TUIC | 只配 Hy2/TUIC 入站，不配别的 | 同理：只建 Hy2/TUIC 入站，订阅里就只有它们 |

> 如果你坚持要用 AimiliVPN 那种“外部 sing-box”串联，也可以：
> 把外部 sing-box 的出站指向某条出口的 SOCKS5 端口和凭据（面板上
> “SOCKS5 / HTTP 访问凭据”里能看到），入站配 Hy2/TUIC。
> 但那是绕路：同一台机器上 y-gate 的 sing-box 已经做了这件事，
> 外挂一层只会多一次转发和一份配置要维护。

## 只支持自建 sing-box 后端

- Hysteria2/TUIC 是 QUIC/UDP 协议，Xray 没有对应的服务端入站，
  3x-ui、S-UI、xray-cf-lite 也没有按本项目的模型接进来。
- 在这些后端上新建 Hy2/TUIC 入站会直接报错，不会静默写成 VLESS：
  - 自建 Xray：`Hysteria2/TUIC 只支持自建 sing-box 后端，当前是 xray……`
  - 3x-ui / S-UI：同理，明确提示暂不支持。
- 后端从 sing-box 切回 Xray 时，如果库里还留着已启用的 Hy2/TUIC 入站，
  `apply` 也会先拦住，不会把它们错写成 VLESS 配置。

切换后端前，先确认面板里显示的是“自建 sing-box”。

## 怎么用

1. 在面板把后端切到自建 sing-box，确认 sing-box 核心已补齐
  （缺核心时按面板提示跑 `miku repair` 补齐）。
2. 新建出口，入口模板选 Hysteria2 或 TUIC；或者先在“新建节点”里
   建一个 Hy2/TUIC 入站，再把它绑定到某个出口。
   - 模板复制（`CloneToTunnels` / 自动补入口）会原样复制协议、UDP、TLS，
     每条出口得到一个独立端口、同一套凭据，和 VLESS 模板的行为一致。
3. 在“新建节点”里选协议：
   - **Hysteria2** / **TUIC**：表单会自动锁定为 **UDP + TLS**，
     路径、Vision、REALITY 字段会隐藏，填了也没用（后端会丢掉）。
   - TLS 域名与证书：留空用自签证书（SNI 默认 `localhost`），
     也可以选已绑定域名与证书，用真实证书就不要再跳过校验。
4. 放行防火墙：**只放行 Hy2/TUIC 的 UDP 端口**和面板端口。
   隧道自身的 SOCKS5 端口是 sing-box 在本机 `127.0.0.1` 上用的内部跳板，
   不需要、也不应该对外放行——它不是要分发的节点。
5. 订阅里拿链接：通用（Base64）、明文链接、Clash、sing-box 四种格式
   都支持 Hy2/TUIC；V2Ray 格式是把链接原样打包，支持 Hy2/TUIC 的
   客户端同样能导入。

## Salamander 混淆与端口跳跃（仅 Hysteria2）

只在新建 Hysteria2 入站时填，TUIC 和其他协议填了会直接报错，
不会静默丢掉：

- **Salamander 混淆**：在“新建节点”里填“混淆口令”，留空就是不混淆。
  生成的 sing-box 入站会带 `obfs: {type: "salamander", password: <口令>}`，
  分享链接里带 `obfs=salamander&obfs-password=<口令>`，Clash 与
  sing-box 订阅也会带上。客户端必须填同样的混淆口令，否则握手直接失败。
- **端口跳跃**：在“新建节点”里填“跳跃端口段”，如 `30010-30020`，
  也可以写成 `30010,30012` 这种逗号列表，最多 32 个端口。
  分享链接写成官方多端口格式：`hysteria2://<口令>@<服务器>:<主端口>,<跳跃段>?…`，
  Clash 订阅用 `ports` 字段，sing-box 客户端订阅用
  `server_ports: [<主端口>, <跳跃段>...]` + `hop_interval: "30s"`。
  客户端会在这些端口之间跳跃，封掉单个端口不会直接断连。
- **服务端是怎么实现的**：sing-box 1.14.3 的服务端入站不能直接监听
  一段端口（实测：`listen_port_range`、`services` 里的 `port_hopping`
  都会被 `sing-box check` 拒绝）。所以 y-gate 为每个跳跃端口再生成
  一个同配置（同用户、同 TLS、同混淆）的影子入站，路由规则对主端口
  和所有影子端口都生效，跳到哪个端口都走同一个绑定出口。
  防火墙要把主端口和跳跃段的每个端口都放行 UDP。
- **模板克隆**：Salamander 口令会照抄到每个出口的克隆入站；
  跳跃段不能照抄（每个出口的跳跃端口必须互不冲突），克隆时会按
  模板段的端口个数，给每个出口单独分配一段连续空闲 UDP 端口，
  范围写在各自的分享链接里，按链接放行即可。
  自动补入口（`ensureExitInbound`）同理。
- **旧节点不变**：已经建好的 Hy2 节点不会自动加上混淆或跳跃，
  因为改了配置旧客户端会立刻断连。要升级就新建一个带混淆/跳跃的
  Hy2 入站，旧的可以留着或删掉；改模板的 Salamander 口令后重新
  克隆会新建入站，旧的需要手动删除。
- **TUIC 没有端口跳跃**：sing-box 的 TUIC 客户端不认 `server_ports`，
  所以 TUIC 入站填跳跃段会被拒绝，不要硬配。

## VMess 已移除

- 自建模式的协议表里没有 VMess 了：新建 VMess 入站直接报不支持，
  前端下拉（嵌入式与独立前端）也不再有 VMess 选项。
- 库里残留的已启用 VMess 入站会在 `apply` 和 sing-box 配置生成时
  被明确拦住，删掉它才能继续生成配置；订阅、出口链接、详情页
  也不再输出 VMess 链接。已停用的 VMess 入站会被跳过，不拦配置。
- 3x-ui / S-UI 后端新建时同样走这套校验，不会再新建 VMess；
  但面板自身数据库里已有的 VMess 入站 y-gate 不会自动删除，
  想彻底不输出 VMess 的话要在面板里手动删掉它们。
- 订阅解析仍能识别外部 VMess 链接（用于导入、转换外部订阅），
  这不是 y-gate 自己生成 VMess 节点，只是解析器不拒绝别人的链接。

## 生成的链接长什么样

Hy2（口令认证，自签证书时带 `insecure=1` 与证书指纹）：

```text
hysteria2://<口令>@<服务器>:<端口>?alpn=h3&insecure=1&pinSHA256=<指纹>&sni=<SNI>#<备注>
```

TUIC（UUID + 口令，固定 bbr + native UDP 中继）：

```text
tuic://<UUID>:<口令>@<服务器>:<端口>?alpn=h3&allow_insecure=1&congestion_control=bbr&sni=<SNI>&udp_relay_mode=native#<备注>
```

用真实域名证书时，链接里没有 `insecure` / `allow_insecure`，
客户端按正常 TLS 校验即可。Hy2 的口令在新建时是 32 位十六进制
（比原来 trojan 的 16 位长一倍），TUIC 的 UUID 是 v4，口令同样是
32 位十六进制。

sing-box 服务端入站（`buildSingBoxConfig` 生成，`sing-box check` 已验过）：

```json
{
  "type": "hysteria2",
  "listen": "0.0.0.0",
  "listen_port": 30001,
  "users": [{ "name": "hysteria2-30001", "password": "<口令>" }],
  "tls": { "enabled": true, "server_name": "example.com", "alpn": ["h3"],
           "certificate_path": "<证书>", "key_path": "<私钥>" }
}
```

```json
{
  "type": "tuic",
  "listen": "0.0.0.0",
  "listen_port": 30002,
  "users": [{ "name": "tuic-30002", "uuid": "<UUID>", "password": "<口令>" }],
  "congestion_control": "bbr",
  "tls": { "enabled": true, "server_name": "example.com", "alpn": ["h3"],
           "certificate_path": "<证书>", "key_path": "<私钥>" }
}
```

## 路由与故障行为

- 入站绑定了出口：流量走该出口隧道的 SOCKS5 出站（`miku-<出口>`），
  出口 IP 就是该 VPN Gate 节点的 IP。
- 入站没绑定出口：走 `direct`，也就是 VPS 自己的直连 IP——
  订阅默认只导出已绑定出口的入站，所以没绑定的不会混进“家宽订阅”。
- 绑定的隧道断了：sing-box 路由规则是 `reject/drop`，连接直接断掉，
  不会静默回落到 VPS 直连（回落会暴露真实 IP，这比断连更糟）。
- 按客户端绑出口（一个入站多个客户端各走不同出口）时，
  sing-box 用 `auth_user`（即客户端的 `name`）分流，Hy2/TUIC 的
  `users[].name` 沿用原来的 `client.Email`，所以这条规则同样生效。

## 端口

- Hy2/TUIC 只用 UDP：随机分配时会同时检查 TCP 和 UDP 是否空闲，
  避免随机到一个已被 UDP 服务占用的端口；手填端口时也会先查 UDP，
  被占就直接报错，不等 sing-box 启动失败再回滚。
- 防火墙、安全组、云厂商端口放行都要开 **UDP**，只开 TCP 是连不上的。
  这是 QUIC 协议最常见的“配好了却连不上”的原因。

## 本次没做的事

- **TUIC 端口跳跃**：sing-box 的 TUIC 客户端不支持 `server_ports`，
  没法像 Hy2 那样配跳跃段，只能用单个端口。
- **跳跃间隔可调**：sing-box 客户端订阅里跳跃间隔固定写 `30s`
  （sing-box 默认值），没有给它单独留一个面板字段。
- **TUIC 0-RTT / heartbeat 等调优参数**：服务端只固定了 `bbr`，
  其余用 sing-box 默认值，避免在没实测过的参数上替用户做决定。

## 改动文件

- `src/inbound_spec.go`：Hy2/TUIC 组合校验（UDP+TLS 固定，拒绝
  TCP/ws/grpc/REALITY/none/Vision），手填端口查 UDP 占用；
  混淆/跳跃只允许 Hy2，TUIC 与其他协议填了报错。
- `src/native.go`：协议表（去掉 VMess）、仅 sing-box 拦挡、切换后端
  残留拦挡、QUIC 口令加长、Hy2/TUIC 分享链接（含混淆与多端口）、
  详情页凭据显示、VMess 残留拦挡与订阅/详情不再输出 VMess、
  模板克隆时 Salamander 照抄、跳跃段按出口重新分配。
- `src/native_singbox.go`：sing-box 的 Hy2/TUIC 入站生成
  （users、TLS h3、TUIC bbr、Hy2 Salamander、跳跃影子入站与
  覆盖所有影子端口的路由规则），VMess 直接报错。
- `src/native_store.go`：入站协议/网络注释，新增混淆口令与跳跃段字段，
  随机分配端口时避开已有的跳跃端口。
- `src/native_entry.go`：模板比对把 Salamander 口令算进去、跳跃段
  不算（每出口不同），自动补入口时跳跃段重新分配。
- `src/sub_formats.go`：订阅解析、Clash、sing-box 客户端转换
  支持 Hy2/TUIC（`hy2://` 也认，`obfs=salamander:口令` 会拆开，
  多端口链接先拆跳跃段再解析，Clash 用 `ports`、sing-box 用
  `server_ports` + `hop_interval`）。
- `src/port.go`：随机端口同时查 TCP/UDP，新增 `udpPortAvailable`、
  跳跃段解析 `parseHopPorts` 与克隆用连续段分配 `allocateHopRange`。
- `src/web.go`：新建节点表单加 Hy2/TUIC，选 QUIC 时锁定 UDP+TLS，
  Hy2 下显示混淆口令与跳跃段输入框，VMess 选项已去掉。
- `src/main.go`：新建入站 API 接收 `obfs_password`、`hop_ports`。
- `frontend/public/index.html`、`frontend/public/static/index-2.js`、
  `frontend/ASSETS.json`：独立前端同步（Hy2/TUIC、混淆/跳跃字段、
  去掉 VMess，资源清单已刷新）。
- `src/panel_sui.go`、`src/xui.go`：S-UI / 3x-ui 明确拒绝 Hy2/TUIC，
  新建时走同一套协议校验，不会再新建 VMess。
- `src/sub.go`、`src/exit_links.go`：订阅与出口链接不再输出 VMess。
- `src/hysteria_tuic_test.go`、`src/hysteria_obfs_hop_test.go`：
  新增测试（见下）。

## 验证（2026-11-03，在本机沙箱）

- `go vet ./...`：通过。
- 新增测试 `TestNormalizeQUICProtocols`、`TestSingBoxQUICInbounds`、
  `TestSingBoxQUICRequiresTLS`、`TestQUICShareLinksAndSubscription`、
  `TestQUICRejectedOnXrayBackend`，以及混淆/跳跃/VMess 移除的
  `TestParseHopPorts`、`TestNormalizeQUICObfsHop`、
  `TestSingBoxQUICObfsHop`、`TestQUICShareLinkObfsHopRoundTrip`、
  `TestVMessRemoved`：全部通过。
- 用项目 `CORE_ASSETS.json` 里指定的 sing-box **1.14.3**
  （SHA256 与清单一致）对生成的 Hy2+TUIC 配置跑
  `sing-box check`：通过；实际 `sing-box run` 后，
  `30001`（Hy2）、`30002`（TUIC）的 UDP 监听都起来了。
  带 Salamander + 跳跃段（`30010-30011`）的 Hy2 配置同样
  `sing-box check` 通过，实际跑起来 `30001`、`30010`、`30011`
  三个 UDP 监听都起来了；`listen_port_range` 与 `services` 里的
  `port_hopping` 在同一版本上实测都被 `check` 拒绝，所以跳跃
  用影子入站实现，而不是那两个字段。
- 全量 `go test ./...`：除 3 个网络命名空间测试外全部通过，
  那 3 个在原版上同样失败（沙箱没有 `CAP_SYS_ADMIN`，
  `operation not permitted`），与本次修改无关。
- 注意：你给的原 zip 里 `src/assets/` 下的插画和国旗 SVG 本来就是空的，
  直接 `go build` 会因 `embed assets/*` 报错，这是原包已有的问题，
  不是本次修改引入的。构建/跑测试前，先把你原来完整仓库里的
  `src/assets/miku-hero-v1.png` 和 `src/assets/flags/*.svg` 放回来；
  本次打包不替你伪造美术文件。
