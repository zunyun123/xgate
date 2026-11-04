package main

import (
	"strings"
	"testing"
)

func relayInbound(proto string, port int) *nativeInbound {
	return &nativeInbound{
		ID: 1, Port: port, Protocol: proto, Network: "udp", Security: "tls",
		Remark: proto + "-relay", Enable: true,
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true},
		Clients: []nativeClient{{Email: proto + "-user", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef", Enable: true}},
	}
}

func TestRelayInboundRoutesTo8500ByDefault(t *testing.T) {
	t.Setenv("MIKU_RELAY_UPSTREAM", "")
	cfg, err := buildSingBoxConfig([]*nativeInbound{relayInbound("hysteria2", 8443), relayInbound("tuic", 8444)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outs := cfg["outbounds"].([]any)
	found := false
	for _, o := range outs {
		m := o.(map[string]any)
		if m["tag"] == relayUpstreamTag {
			found = true
			if m["server"] != "127.0.0.1" || m["server_port"] != 8500 || m["type"] != "socks" {
				t.Fatalf("串联上游不是默认 8500 SOCKS5: %v", m)
			}
		}
	}
	if !found {
		t.Fatal("没有生成 relay-upstream 出站")
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("应有 2 条串联路由规则，实际 %d: %v", len(rules), rules)
	}
	for _, r := range rules {
		if r.(map[string]any)["outbound"] != relayUpstreamTag {
			t.Fatalf("未绑出口的串联入站没有走 8500: %v", r)
		}
	}
	ins := cfg["inbounds"].([]any)
	hy := ins[0].(map[string]any)
	if hy["type"] != "hysteria2" {
		t.Fatalf("hy2 类型不对: %v", hy)
	}
	if users := hy["users"].([]any); len(users) != 1 || users[0].(map[string]any)["password"] != "0123456789abcdef" {
		t.Fatalf("hy2 凭据不对: %v", users)
	}
	tu := ins[1].(map[string]any)
	if tu["type"] != "tuic" || tu["congestion_control"] != "bbr" {
		t.Fatalf("tuic 配置不对: %v", tu)
	}
}

func TestRelayInboundBoundToTunnelOverrides8500(t *testing.T) {
	ib := relayInbound("hysteria2", 8443)
	ib.BoundTo = "jp"
	tunnels := []*Tunnel{{Port: 35000, Status: "up", Node: Node{HostName: "jp"}}}
	cfg, err := buildSingBoxConfig([]*nativeInbound{ib}, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["outbound"] != "miku-jp" {
		t.Fatalf("绑了出口的串联入站应走隧道，实际 %v", rules)
	}
}

func TestRelayShareLinks(t *testing.T) {
	hy := shareLink(relayInbound("hysteria2", 8443), relayInbound("hysteria2", 8443).Clients[0], "203.0.113.1")
	if !strings.HasPrefix(hy, "hysteria2://0123456789abcdef@203.0.113.1:8443?") || !strings.Contains(hy, "insecure=1") || !strings.Contains(hy, "sni=example.com") {
		t.Fatalf("hy2 链接不对: %s", hy)
	}
	tu := shareLink(relayInbound("tuic", 8444), relayInbound("tuic", 8444).Clients[0], "203.0.113.1")
	if !strings.HasPrefix(tu, "tuic://11111111-2222-4333-8444-555555555555:0123456789abcdef@203.0.113.1:8444?") || !strings.Contains(tu, "allow_insecure=1") {
		t.Fatalf("tuic 链接不对: %s", tu)
	}
	// 订阅转换不能因为多了这两种协议就把整个订阅拖垮。
	if _, err := parseSubscriptionNode(hy); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSubscriptionNode(tu); err != nil {
		t.Fatal(err)
	}
	if _, _, err := formatSubscription([]string{hy, tu}, "singbox"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := formatSubscription([]string{hy, tu}, "clash"); err != nil {
		t.Fatal(err)
	}
}

func TestVMessRemoved(t *testing.T) {
	if _, err := normalizeInboundSpec(NewInboundSpec{Protocol: "vmess"}, map[int]bool{}); err == nil {
		t.Fatal("VMess 新建应被拒绝")
	}
	if _, err := parseSubscriptionNode("vmess://eyJ2IjogIjIifQ=="); err == nil {
		t.Fatal("vmess:// 链接应被拒绝")
	}
	cfg, err := buildSingBoxConfig([]*nativeInbound{{Enable: true, Protocol: "vmess", Port: 10003, Remark: "legacy"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg["inbounds"].([]any)) != 0 {
		t.Fatal("残留 VMess 入站不应生成运行配置")
	}
	if link := shareLink(&nativeInbound{Protocol: "vmess", Port: 10003, Remark: "legacy"}, nativeClient{ID: "x"}, "203.0.113.1"); link != "" {
		t.Fatalf("残留 VMess 入站不应输出链接: %s", link)
	}
}

func TestRelaySpecValidation(t *testing.T) {
	if _, err := normalizeInboundSpec(NewInboundSpec{Protocol: "hysteria2", Network: "ws"}, map[int]bool{}); err == nil {
		t.Fatal("hy2 + ws 应被拒绝")
	}
	if _, err := normalizeInboundSpec(NewInboundSpec{Protocol: "tuic", Security: "none"}, map[int]bool{}); err == nil {
		t.Fatal("tuic + none 应被拒绝")
	}
	ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: "hysteria2"}, map[int]bool{})
	if err != nil || ns.Network != "udp" || ns.Security != "tls" {
		t.Fatalf("hy2 默认应为 udp+tls，实际 %+v, err=%v", ns, err)
	}
}
