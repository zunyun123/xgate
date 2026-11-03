package main

import (
	"strings"
	"testing"
)

func TestNormalizeQUICProtocols(t *testing.T) {
	// 留空时补成 UDP+TLS，ws 路径/Host 头直接丢掉。
	for _, proto := range []string{"hysteria2", "tuic"} {
		ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: proto, Path: "/x", Host: "example.com"}, map[int]bool{})
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if ns.Network != "udp" || ns.Security != "tls" || ns.Path != "" || ns.Host != "" {
			t.Fatalf("%s: 归一化结果不对: %+v", proto, ns)
		}
	}
	// 填了别的组合要报错，不能静默改成用户没要的组合。
	for _, spec := range []NewInboundSpec{
		{Protocol: "hysteria2", Network: "tcp"},
		{Protocol: "hysteria2", Network: "ws"},
		{Protocol: "tuic", Security: "none"},
		{Protocol: "tuic", Security: "reality"},
		{Protocol: "hysteria2", Vision: true},
	} {
		if _, err := normalizeInboundSpec(spec, map[int]bool{}); err == nil {
			t.Fatalf("%+v 应被拒绝", spec)
		}
	}
}

func TestSingBoxQUICInbounds(t *testing.T) {
	hy2 := &nativeInbound{
		ID: 1, Port: 30001, Protocol: "hysteria2", Network: "udp", Security: "tls",
		Remark: "hy2", Enable: true, BoundTo: "jp",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true, CertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Clients: []nativeClient{{Email: "hysteria2-30001", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	tuic := &nativeInbound{
		ID: 2, Port: 30002, Protocol: "tuic", Network: "udp", Security: "tls",
		Remark: "tuic", Enable: true, BoundTo: "jp",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true},
		Clients: []nativeClient{{Email: "tuic-30002", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	tunnels := []*Tunnel{{Port: 35000, Status: "up", Node: Node{HostName: "jp"}}}
	cfg, err := buildSingBoxConfig([]*nativeInbound{hy2, tuic}, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	ins := cfg["inbounds"].([]any)
	if len(ins) != 2 {
		t.Fatalf("入站数 = %d, want 2", len(ins))
	}
	// Hysteria2：只认口令，TLS 必须带 h3，没有 transport。
	h := ins[0].(map[string]any)
	if h["type"] != "hysteria2" {
		t.Fatalf("hy2 type = %v", h["type"])
	}
	if _, ok := h["transport"]; ok {
		t.Fatal("hy2 不应有 transport")
	}
	users := h["users"].([]any)
	if users[0].(map[string]any)["password"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("hy2 users = %v", users)
	}
	tls := h["tls"].(map[string]any)
	if tls["enabled"] != true || tls["alpn"].([]string)[0] != "h3" {
		t.Fatalf("hy2 tls = %v", tls)
	}
	// TUIC：UUID + 口令 + bbr。
	u := ins[1].(map[string]any)
	if u["type"] != "tuic" || u["congestion_control"] != "bbr" {
		t.Fatalf("tuic inbound = %v", u)
	}
	tusers := u["users"].([]any)
	if tusers[0].(map[string]any)["uuid"] != "11111111-2222-4333-8444-555555555555" || tusers[0].(map[string]any)["password"] == "" {
		t.Fatalf("tuic users = %v", tusers)
	}
	// 入站级绑定：Hy2/TUIC 的流量要走到 jp 隧道的 SOCKS5 出站，
	// 而不是 sing-box 的 direct（那会暴露 VPS 直连 IP）。
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	found := false
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["outbound"] == "miku-jp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("没有到 miku-jp 的路由规则: %v", rules)
	}
	// 出站里必须有 jp 隧道的 SOCKS5（对应 AimiliVPN 的 8500 思路，
	// 但 y-gate 是每条出口一个 SOCKS 端口，不是共用一个 8500）。
	outs := cfg["outbounds"].([]any)
	socks := false
	for _, o := range outs {
		out := o.(map[string]any)
		if out["type"] == "socks" && out["server_port"] == 35000 {
			socks = true
		}
	}
	if !socks {
		t.Fatalf("出站里没有 jp 隧道的 SOCKS5: %v", outs)
	}
}

func TestSingBoxQUICRequiresTLS(t *testing.T) {
	_, err := buildSingBoxConfig([]*nativeInbound{{Enable: true, Protocol: "hysteria2", Network: "udp", Remark: "hy2"}}, nil)
	if err == nil {
		t.Fatal("没有 TLS 的 Hy2 入站应被拒绝")
	}
}

func TestQUICShareLinksAndSubscription(t *testing.T) {
	hy2 := &nativeInbound{
		Port: 30001, Protocol: "hysteria2", Network: "udp", Security: "tls", Remark: "hy2",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true, CertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Clients: []nativeClient{{Email: "hy2", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	tuic := &nativeInbound{
		Port: 30002, Protocol: "tuic", Network: "udp", Security: "tls", Remark: "tuic",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true},
		Clients: []nativeClient{{Email: "tuic", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	hy2Link := shareLink(hy2, hy2.Clients[0], "203.0.113.1")
	if !strings.HasPrefix(hy2Link, "hysteria2://0123456789abcdef0123456789abcdef@203.0.113.1:30001?") || !strings.Contains(hy2Link, "sni=example.com") || !strings.Contains(hy2Link, "insecure=1") || !strings.Contains(hy2Link, "alpn=h3") {
		t.Fatalf("hy2 链接不对: %s", hy2Link)
	}
	tuicLink := shareLink(tuic, tuic.Clients[0], "203.0.113.1")
	if !strings.HasPrefix(tuicLink, "tuic://11111111-2222-4333-8444-555555555555:0123456789abcdef0123456789abcdef@203.0.113.1:30002?") || !strings.Contains(tuicLink, "congestion_control=bbr") || !strings.Contains(tuicLink, "udp_relay_mode=native") || !strings.Contains(tuicLink, "allow_insecure=1") {
		t.Fatalf("tuic 链接不对: %s", tuicLink)
	}
	// 链接要能再被订阅解析吃回去，否则 Clash/sing-box 订阅会整体报错。
	for _, link := range []string{hy2Link, tuicLink} {
		n, err := parseSubscriptionNode(link)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", link, err)
		}
		if n.Network != "udp" || n.Security != "tls" {
			t.Fatalf("解析结果不对: %+v", n)
		}
	}
	// Clash 与 sing-box 订阅不能因为 udp 传输就报错。
	clash, _, err := formatSubscription([]string{hy2Link, tuicLink}, "clash")
	if err != nil {
		t.Fatalf("clash 订阅失败: %v", err)
	}
	if !strings.Contains(clash, "hysteria2") || !strings.Contains(clash, "tuic") || !strings.Contains(clash, "congestion-controller") {
		t.Fatalf("clash 订阅内容不对:\n%s", clash)
	}
	sing, _, err := formatSubscription([]string{hy2Link, tuicLink}, "singbox")
	if err != nil {
		t.Fatalf("sing-box 订阅失败: %v", err)
	}
	if !strings.Contains(sing, `"type": "hysteria2"`) || !strings.Contains(sing, `"type": "tuic"`) || !strings.Contains(sing, "congestion_control") {
		t.Fatalf("sing-box 订阅内容不对:\n%s", sing)
	}
}

func TestQUICRejectedOnXrayBackend(t *testing.T) {
	n := &Native{store: &nativeStore{NextID: 1}, proc: &xrayProc{core: "xray"}}
	_, err := n.CreateInbound(NewInboundSpec{Protocol: "hysteria2"}, nil)
	if err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Fatalf("Xray 后端应明确拒绝 Hy2，实际: %v", err)
	}
	_, err = n.CreateInbound(NewInboundSpec{Protocol: "tuic"}, nil)
	if err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Fatalf("Xray 后端应明确拒绝 TUIC，实际: %v", err)
	}
}
