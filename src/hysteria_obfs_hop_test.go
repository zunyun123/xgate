package main

import (
	"strings"
	"testing"
)

func TestParseHopPorts(t *testing.T) {
	ports, err := parseHopPorts("30010-30012,30015")
	if err != nil || len(ports) != 4 || ports[0] != 30010 || ports[3] != 30015 {
		t.Fatalf("解析结果不对: %v %v", ports, err)
	}
	if got := hopPortsString(ports); got != "30010-30012,30015" {
		t.Fatalf("压回字符串不对: %s", got)
	}
	for _, bad := range []string{"30020-30010", "0", "65536", "30010-", "abc", "30000-30040"} {
		if _, err := parseHopPorts(bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
}

func TestNormalizeQUICObfsHop(t *testing.T) {
	// Hy2 可以同时填混淆和跳跃段。
	ns, err := normalizeInboundSpec(NewInboundSpec{Protocol: "hysteria2", Port: 30001, ObfsPassword: "obfs0123456789ab", HopPorts: "30010-30012"}, map[int]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if ns.ObfsPassword != "obfs0123456789ab" || ns.HopPorts != "30010-30012" {
		t.Fatalf("归一化丢了混淆/跳跃: %+v", ns)
	}
	// TUIC 和其他协议填了只能报错，不能静默丢掉。
	for _, spec := range []NewInboundSpec{
		{Protocol: "tuic", Port: 30002, ObfsPassword: "x"},
		{Protocol: "tuic", Port: 30002, HopPorts: "30010-30012"},
		{Protocol: "vless", ObfsPassword: "x"},
		{Protocol: "trojan", HopPorts: "30010-30012"},
		// 跳跃段不能含主端口，也不能撞已有端口。
		{Protocol: "hysteria2", Port: 30001, HopPorts: "30001-30002"},
		{Protocol: "hysteria2", Port: 30001, HopPorts: "30010-30012"},
	} {
		used := map[int]bool{}
		if spec.Port == 30001 && spec.HopPorts == "30010-30012" {
			used[30011] = true
		}
		if _, err := normalizeInboundSpec(spec, used); err == nil {
			t.Fatalf("%+v 应被拒绝", spec)
		}
	}
}

func TestSingBoxQUICObfsHop(t *testing.T) {
	hy2 := &nativeInbound{
		ID: 1, Port: 30001, Protocol: "hysteria2", Network: "udp", Security: "tls",
		Remark: "hy2", Enable: true, BoundTo: "jp",
		ObfsPassword: "obfs0123456789ab", HopPorts: "30010-30011",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true},
		Clients: []nativeClient{{Email: "hysteria2-30001", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	tunnels := []*Tunnel{{Port: 35000, Status: "up", Node: Node{HostName: "jp"}}}
	cfg, err := buildSingBoxConfig([]*nativeInbound{hy2}, tunnels)
	if err != nil {
		t.Fatal(err)
	}
	ins := cfg["inbounds"].([]any)
	// 主入站 + 两个跳跃影子入站。
	if len(ins) != 3 {
		t.Fatalf("入站数 = %d, want 3", len(ins))
	}
	main := ins[0].(map[string]any)
	if obfs, ok := main["obfs"].(map[string]any); !ok || obfs["type"] != "salamander" || obfs["password"] != "obfs0123456789ab" {
		t.Fatalf("主入站混淆不对: %v", main["obfs"])
	}
	for i, port := range []int{30010, 30011} {
		shadow := ins[1+i].(map[string]any)
		if shadow["listen_port"] != port || shadow["tag"] != "in-30010-udp" && shadow["tag"] != "in-30011-udp" {
			t.Fatalf("影子入站不对: %v", shadow)
		}
		if shadow["obfs"].(map[string]any)["password"] != "obfs0123456789ab" {
			t.Fatalf("影子入站没带混淆: %v", shadow)
		}
	}
	// 路由规则要覆盖主 tag 和影子 tag，否则跳到影子端口的流量会直连。
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("规则数 = %d, want 1", len(rules))
	}
	rule := rules[0].(map[string]any)
	if rule["outbound"] != "miku-jp" {
		t.Fatalf("规则出站不对: %v", rule)
	}
	inbounds := rule["inbound"].([]string)
	if len(inbounds) != 3 || inbounds[0] != "in-30001-udp" || inbounds[1] != "in-30010-udp" || inbounds[2] != "in-30011-udp" {
		t.Fatalf("规则入站 tag 不对: %v", inbounds)
	}
}

func TestQUICShareLinkObfsHopRoundTrip(t *testing.T) {
	hy2 := &nativeInbound{
		Port: 30001, Protocol: "hysteria2", Network: "udp", Security: "tls", Remark: "hy2",
		ObfsPassword: "obfs0123456789ab", HopPorts: "30010-30020",
		TLS:     &tlsConfig{ServerName: "example.com", CertFile: "/tmp/x.crt", KeyFile: "/tmp/x.key", SelfSigned: true, CertSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Clients: []nativeClient{{Email: "hy2", ID: "11111111-2222-4333-8444-555555555555", Password: "0123456789abcdef0123456789abcdef", Enable: true}},
	}
	link := shareLink(hy2, hy2.Clients[0], "203.0.113.1")
	if !strings.Contains(link, "@203.0.113.1:30001,30010-30020?") || !strings.Contains(link, "obfs=salamander") || !strings.Contains(link, "obfs-password=obfs0123456789ab") {
		t.Fatalf("带混淆/跳跃的链接不对: %s", link)
	}
	n, err := parseSubscriptionNode(link)
	if err != nil {
		t.Fatal(err)
	}
	if n.Port != 30001 || n.HopPorts != "30010-30020" || n.Obfs != "salamander" || n.ObfsPassword != "obfs0123456789ab" {
		t.Fatalf("解析回跳跃/混淆不对: %+v", n)
	}
	clash, _, err := formatSubscription([]string{link}, "clash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(clash, "ports") || !strings.Contains(clash, "30010-30020") {
		t.Fatalf("clash 订阅没带跳跃段:\n%s", clash)
	}
	sing, _, err := formatSubscription([]string{link}, "singbox")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sing, "server_ports") || !strings.Contains(sing, "30010-30020") || !strings.Contains(sing, "hop_interval") {
		t.Fatalf("sing-box 订阅没带跳跃:\n%s", sing)
	}
}

func TestVMessRemoved(t *testing.T) {
	if nativeProtocols["vmess"] {
		t.Fatal("nativeProtocols 里还有 vmess")
	}
	if _, err := normalizeInboundSpec(NewInboundSpec{Protocol: "vmess"}, map[int]bool{}); err == nil {
		t.Fatal("新建 VMess 应被拒绝")
	}
	_, err := buildSingBoxConfig([]*nativeInbound{{Enable: true, Protocol: "vmess", Remark: "old-vmess"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "VMess") {
		t.Fatalf("sing-box 配置应明确拒绝 VMess，实际: %v", err)
	}
	n := &Native{store: &nativeStore{NextID: 1, Inbounds: []*nativeInbound{{Enable: true, Protocol: "vmess", Remark: "old-vmess", Port: 30003}}}, proc: &xrayProc{core: "sing-box"}}
	if err := n.apply(nil); err == nil || !strings.Contains(err.Error(), "VMess") {
		t.Fatalf("apply 应明确拒绝残留 VMess，实际: %v", err)
	}
}
