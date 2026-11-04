package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func findSingBox(dir string) (string, error) {
	for _, path := range []string{filepath.Join(dir, "bin", "sing-box"), "/usr/local/bin/sing-box", "/usr/bin/sing-box", "/usr/local/s-ui/bin/sing-box"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0 {
			return path, nil
		}
	}
	return "", fmt.Errorf("未找到 sing-box，请在VPS运行 miku repair 补齐核心")
}

func base64KeyPublic(private string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func generatedReality(spec NewInboundSpec) (*realityConfig, error) {
	dest := strings.TrimSpace(spec.Dest)
	if dest == "" {
		dest = "www.microsoft.com:443"
	}
	host, _, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, fmt.Errorf("REALITY目标需填写 域名:端口")
	}
	names := []string{}
	for _, name := range strings.Split(spec.ServerNames, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		names = append(names, host)
	}
	if err := checkRealityDest(dest, names[0]); err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sid := strings.TrimSpace(spec.ShortID)
	if sid == "" {
		sid = randomShortID()
	}
	if raw, err := hex.DecodeString(sid); err != nil || len(raw) > 8 {
		return nil, fmt.Errorf("REALITY short ID应为最多16位、偶数长度的十六进制")
	}
	fp := strings.TrimSpace(spec.Fingerprint)
	if fp == "" {
		fp = "chrome"
	}
	return &realityConfig{Dest: dest, ServerNames: names, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortIDs: []string{sid}, Fingerprint: fp}, nil
}

// relayUpstreamTag 是串联出口的固定 tag：Hysteria2/TUIC 入站
// 没有绑具体出口时，全部走这条出站。
const relayUpstreamTag = "relay-upstream"

// relayUpstream 解析串联上游 SOCKS5 地址。
//
// 默认 127.0.0.1:8500：这就是 AimiliVPN 那种“本地统一出口”
// 的约定——AimiliVPN 在本机把 VPN Gate 家宽通道汇成一个
// SOCKS5/HTTP 出口，miku-gate 不需要也不应该去改它的拨号逻辑，
// 只需要把 Hy2/TUIC 客户端的流量交给它。
// 想改上游时不用改代码，起服务前设环境变量即可：
//
//	MIKU_RELAY_UPSTREAM=127.0.0.1:8500
//	MIKU_RELAY_UPSTREAM_USER= / MIKU_RELAY_UPSTREAM_PASS=（上游要认证时才填）
//
// 上游无认证时不带 username/password，避免 sing-box 把空凭据发过去。
func relayUpstream() (host string, port int, user, pass string) {
	host, port = "127.0.0.1", 8500
	if raw := strings.TrimSpace(os.Getenv("MIKU_RELAY_UPSTREAM")); raw != "" {
		if h, p, err := net.SplitHostPort(raw); err == nil {
			host = h
			fmt.Sscanf(p, "%d", &port)
		} else {
			host = raw
		}
	}
	return host, port, os.Getenv("MIKU_RELAY_UPSTREAM_USER"), os.Getenv("MIKU_RELAY_UPSTREAM_PASS")
}

func buildSingBoxConfig(inbounds []*nativeInbound, tunnels []*Tunnel) (map[string]any, error) {
	live := map[string]bool{}
	outs := []any{map[string]any{"type": "direct", "tag": "direct"}}
	for _, tunnel := range tunnels {
		if tunnel.Status != "up" {
			continue
		}
		live[sanitizeTag(tunnel.Node.HostName)] = true
		cred := tunnel.credential()
		outs = append(outs, map[string]any{"type": "socks", "tag": tunnelTag(tunnel), "server": "127.0.0.1", "server_port": tunnel.Port, "version": "5", "username": cred.User, "password": cred.Pass})
	}
	// 只要有一个启用的串联入站，就挂上 8500 上游出站。
	// 没有 Hy2/TUIC 时不挂，避免无意义地多一条出站。
	hasRelay := false
	for _, ib := range inbounds {
		if ib.Enable && isRelayProtocol(ib.Protocol) {
			hasRelay = true
			break
		}
	}
	if hasRelay {
		host, port, user, pass := relayUpstream()
		up := map[string]any{"type": "socks", "tag": relayUpstreamTag, "server": host, "server_port": port, "version": "5"}
		if user != "" {
			up["username"] = user
			up["password"] = pass
		}
		outs = append(outs, up)
	}
	ins, rules := []any{}, []any{}
	for _, ib := range inbounds {
		if !ib.Enable {
			continue
		}
		// VMess 已移除：残留入站直接跳过，不生成配置、不留路由。
		if ib.Protocol == "vmess" {
			continue
		}
		// Hysteria2/TUIC 串联入站：不走 vless 那套 users/transport。
		// sing-box 里它们是独立的 inbound 类型，凭据写法也不同：
		// Hy2 只有 password，TUIC 是 uuid + password，且都强制 TLS。
		if isRelayProtocol(ib.Protocol) {
			if ib.Security != "tls" || ib.TLS == nil {
				return nil, fmt.Errorf("节点 %s：%s 必须配 TLS 证书", ib.Remark, ib.Protocol)
			}
			in := map[string]any{"type": ib.Protocol, "tag": ib.tag(), "listen": "0.0.0.0", "listen_port": ib.Port,
				"tls": map[string]any{"enabled": true, "server_name": ib.TLS.ServerName, "certificate_path": ib.TLS.CertFile, "key_path": ib.TLS.KeyFile}}
			users := []any{}
			for _, client := range ib.Clients {
				if !client.Enable {
					continue
				}
				if ib.Protocol == "hysteria2" {
					users = append(users, map[string]any{"password": client.Password})
				} else {
					users = append(users, map[string]any{"uuid": client.ID, "password": client.Password})
				}
			}
			in["users"] = users
			if ib.Protocol == "tuic" {
				// 注意：udp_relay_mode 是 TUIC 客户端出站的字段，
				// 服务端入站没有它，写上 sing-box check 会直接报
				// unknown field，所以服务端只留 congestion_control。
				in["congestion_control"] = "bbr"
			}
			ins = append(ins, in)
			// 路由：绑了出口就走该出口的隧道 SOCKS（和 vless 保持一致），
			// 没绑就走串联上游 8500，绝不落到 final=direct 去直连，
			// 否则“只输出 Hy2/TUIC、出口走家宽”这个目标就被绕过了。
			// Hy2/TUIC 的用户没有 name 字段，做不了按 auth_user 的
			// 逐客户端路由，所以只认入站级 BoundTo，客户端级 BoundTo
			// 在只有一个默认客户端时同样生效（取第一个已启用客户端的）。
			bound := ib.BoundTo
			if bound == "" {
				for _, client := range ib.Clients {
					if client.Enable && client.BoundTo != "" {
						bound = client.BoundTo
						break
					}
				}
			}
			if bound != "" {
				rule := map[string]any{"inbound": []string{ib.tag()}, "action": "reject", "method": "drop"}
				if live[bound] {
					rule = map[string]any{"inbound": []string{ib.tag()}, "action": "route", "outbound": xuiTagPrefix + bound}
				}
				rules = append(rules, rule)
			} else {
				rules = append(rules, map[string]any{"inbound": []string{ib.tag()}, "action": "route", "outbound": relayUpstreamTag})
			}
			continue
		}
		if ib.netOrTCP() == "xhttp" {
			return nil, fmt.Errorf("节点 %s 使用XHTTP，请选择Xray核心；sing-box不支持此传输", ib.Remark)
		}
		in := map[string]any{"type": ib.Protocol, "tag": ib.tag(), "listen": "0.0.0.0", "listen_port": ib.Port}
		users := []any{}
		for _, client := range ib.Clients {
			if !client.Enable {
				continue
			}
			user := map[string]any{"name": client.Email}
			if ib.Protocol == "trojan" {
				user["password"] = client.Password
			} else {
				user["uuid"] = client.ID
				if ib.Protocol == "vless" && client.Flow != "" {
					user["flow"] = client.Flow
				}
			}
			users = append(users, user)
		}
		in["users"] = users
		if ib.Security == "tls" && ib.TLS != nil {
			in["tls"] = map[string]any{"enabled": true, "server_name": ib.TLS.ServerName, "certificate_path": ib.TLS.CertFile, "key_path": ib.TLS.KeyFile}
		}
		if ib.Security == "reality" && ib.Reality != nil {
			host, port, err := net.SplitHostPort(ib.Reality.Dest)
			if err != nil || len(ib.Reality.ServerNames) == 0 {
				return nil, fmt.Errorf("节点REALITY目标无效")
			}
			var number int
			fmt.Sscanf(port, "%d", &number)
			in["tls"] = map[string]any{"enabled": true, "server_name": ib.Reality.ServerNames[0], "reality": map[string]any{"enabled": true, "handshake": map[string]any{"server": host, "server_port": number}, "private_key": ib.Reality.PrivateKey, "short_id": ib.Reality.ShortIDs}}
		}
		switch ib.netOrTCP() {
		case "ws":
			transport := map[string]any{"type": "ws", "path": ib.Path}
			if ib.Host != "" {
				transport["headers"] = map[string][]string{"Host": {ib.Host}}
			}
			in["transport"] = transport
		case "grpc":
			in["transport"] = map[string]any{"type": "grpc", "service_name": strings.TrimPrefix(ib.Path, "/")}
		case "httpupgrade":
			in["transport"] = map[string]any{"type": "httpupgrade", "path": ib.Path, "host": ib.Host}
		}
		ins = append(ins, in)
		for _, client := range ib.Clients {
			if !client.Enable || client.BoundTo == "" {
				continue
			}
			rule := map[string]any{"inbound": []string{ib.tag()}, "auth_user": []string{client.Email}, "action": "reject", "method": "drop"}
			if live[client.BoundTo] {
				rule = map[string]any{"inbound": []string{ib.tag()}, "auth_user": []string{client.Email}, "action": "route", "outbound": xuiTagPrefix + client.BoundTo}
			}
			rules = append(rules, rule)
		}
		if ib.BoundTo != "" {
			rule := map[string]any{"inbound": []string{ib.tag()}, "action": "reject", "method": "drop"}
			if live[ib.BoundTo] {
				rule = map[string]any{"inbound": []string{ib.tag()}, "action": "route", "outbound": xuiTagPrefix + ib.BoundTo}
			}
			rules = append(rules, rule)
		}
	}
	return map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": ins, "outbounds": outs, "route": map[string]any{"rules": rules, "final": "direct"}}, nil
}

func (p *xrayProc) kind() string {
	if p.core == "sing-box" {
		return "sing-box"
	}
	return "xray"
}

func (p *xrayProc) verify(path string) error {
	if p.kind() != "sing-box" {
		return verifyXrayConfig(p.bin, path)
	}
	output, err := cmdCombined(exec.Command(p.bin, "check", "-c", path))
	if err != nil {
		return fmt.Errorf("sing-box配置校验失败: %s", trimOutput(output))
	}
	return nil
}
