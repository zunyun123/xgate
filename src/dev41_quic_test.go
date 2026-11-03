package main

import (
	"strings"
	"testing"
)

// hysteria2/tuic 入站校验：传输/安全层强制为 udp/tls，端口自动分配。
func TestNormalizeQuicSpec(t *testing.T) {
	ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: "hysteria2"}, map[int]bool{})
	if err != nil {
		t.Fatalf("hysteria2 校验失败: %v", err)
	}
	if ns.Network != "udp" || ns.Security != "tls" {
		t.Fatalf("hysteria2 应固定 udp/tls, 得到 %s/%s", ns.Network, ns.Security)
	}
	if ns.Port == 0 {
		t.Fatal("端口应自动分配")
	}

	if _, err := normalizeInboundSpec(NewInboundSpec{Protocol: "tuic", Port: 8443}, map[int]bool{8443: true}); err == nil {
		t.Fatal("端口占用应报错")
	}
}

// sing-box 配置：QUIC 入站结构与 vless/trojan 不同。
func TestBuildSingBoxQuicConfig(t *testing.T) {
	ib := &nativeInbound{
		ID: 1, Port: 8443, Protocol: "hysteria2", Network: "udp", Security: "tls",
		Remark: "hy2", Enable: true,
		TLS: &tlsConfig{ServerName: "example.com", CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"},
		Clients: []nativeClient{{Email: "u1", Password: "pw123", Enable: true}},
	}
	in, err := singBoxQuicInbound(ib)
	if err != nil {
		t.Fatalf("生成 hysteria2 入站失败: %v", err)
	}
	if in["type"] != "hysteria2" || in["listen_port"] != 8443 {
		t.Fatalf("入站字段错误: %v", in)
	}
	users := in["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["password"] != "pw123" {
		t.Fatalf("hysteria2 用户结构错误: %v", users)
	}

	// TUIC: uuid+password 双凭据 + bbr + alpn h3
	ib2 := &nativeInbound{
		ID: 2, Port: 8444, Protocol: "tuic", Network: "udp", Security: "tls",
		Remark: "tuic", Enable: true,
		TLS: &tlsConfig{CertFile: "/tmp/c.pem", KeyFile: "/tmp/k.pem"},
		Clients: []nativeClient{{Email: "u2", ID: "uuid-1", Password: "pw2", Enable: true}},
	}
	in2, err := singBoxQuicInbound(ib2)
	if err != nil {
		t.Fatalf("生成 tuic 入站失败: %v", err)
	}
	if in2["congestion_control"] != "bbr" || in2["udp_relay_mode"] != "native" {
		t.Fatalf("tuic 应带 bbr/native: %v", in2)
	}
	if tls := in2["tls"].(map[string]any); tls["alpn"].([]string)[0] != "h3" {
		t.Fatalf("tuic TLS 应带 alpn h3")
	}

	// 缺证书应报错
	ib.TLS = nil
	if _, err := singBoxQuicInbound(ib); err == nil {
		t.Fatal("缺TLS证书应报错")
	}
}

// 分享链接格式。
func TestQuicShareLinks(t *testing.T) {
	host := "1.2.3.4"
	hy2 := &nativeInbound{
		Port: 8443, Protocol: "hysteria2", Network: "udp", Security: "tls", Remark: "hy2",
		TLS: &tlsConfig{ServerName: "localhost", SelfSigned: true},
		Clients: []nativeClient{{Email: "u", Password: "secret", Enable: true}},
	}
	link := shareLink(hy2, hy2.Clients[0], host)
	if !strings.HasPrefix(link, "hysteria2://secret@1.2.3.4:8443?") || !strings.Contains(link, "insecure=1") {
		t.Fatalf("hysteria2 链接格式错误: %s", link)
	}

	tuic := &nativeInbound{
		Port: 8444, Protocol: "tuic", Network: "udp", Security: "tls", Remark: "tuic",
		TLS: &tlsConfig{ServerName: "example.com"},
		Clients: []nativeClient{{Email: "u", ID: "uuid-x", Password: "pw", Enable: true}},
	}
	link2 := shareLink(tuic, tuic.Clients[0], host)
	if !strings.HasPrefix(link2, "tuic://uuid-x:pw@1.2.3.4:8444?") ||
		!strings.Contains(link2, "congestion_control=bbr") || !strings.Contains(link2, "sni=example.com") {
		t.Fatalf("tuic 链接格式错误: %s", link2)
	}
}

// 订阅解析 + clash/sing-box 导出往返。
func TestQuicSubscriptionRoundtrip(t *testing.T) {
	link := "hysteria2://secret@1.2.3.4:8443?insecure=1&sni=example.com#JP-hy2"
	n, err := parseSubscriptionNode(link)
	if err != nil {
		t.Fatalf("解析 hysteria2 链接失败: %v", err)
	}
	if n.Protocol != "hysteria2" || n.Password != "secret" || n.ServerName != "example.com" || !n.Insecure {
		t.Fatalf("hysteria2 解析字段错误: %+v", n)
	}
	cp, err := n.clashProxy()
	if err != nil || cp["type"] != "hysteria2" || cp["password"] != "secret" {
		t.Fatalf("clash 导出错误: %v err=%v", cp, err)
	}
	sp, err := n.singBoxProxy()
	if err != nil || sp["type"] != "hysteria2" {
		t.Fatalf("singbox 导出错误: %v err=%v", sp, err)
	}

	tuic := "tuic://uuid-x:pw@1.2.3.4:8444?congestion_control=bbr&alpn=h3&sni=example.com#JP-tuic"
	n2, err := parseSubscriptionNode(tuic)
	if err != nil {
		t.Fatalf("解析 tuic 链接失败: %v", err)
	}
	if n2.UUID != "uuid-x" || n2.Password != "pw" {
		t.Fatalf("tuic 解析字段错误: %+v", n2)
	}
	cp2, err := n2.clashProxy()
	if err != nil || cp2["uuid"] != "uuid-x" || cp2["congestion-controller"] != "bbr" {
		t.Fatalf("tuic clash 导出错误: %v err=%v", cp2, err)
	}
}
