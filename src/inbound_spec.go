package main

import (
	"fmt"
	"strings"
)

// normalizedSpec 是 NewInboundSpec 过完校验、补完默认值之后的样子。
// 两种后端都从这里出发：自建模式落成 nativeInbound，3x-ui 模式转成面板的 add 载荷。
type normalizedSpec struct {
	Protocol string
	Network  string
	Security string
	Port     int
	Path     string
	Host     string
	Remark   string
	Flow     string
}

// isRelayProtocol 判断是不是串联输出协议：Hysteria2 / TUIC。
//
// 这两个协议只有 sing-box 能做服务端入站（Xray 入站没有它们），
// 而且它们自带 UDP/QUIC 传输、强制 TLS，不能套 ws/grpc/REALITY/Vision。
// 它们的流量不直接出公网，而是经 sing-box 转给下游 SOCKS5 出口
// （默认是 AimiliVPN 式本地 8500，见 relayUpstream），
// 绑了具体出口时则走该出口的隧道 SOCKS。
func isRelayProtocol(proto string) bool {
	return proto == "hysteria2" || proto == "tuic"
}

// normalizeInboundSpec 校验协议组合并补上默认值。
//
// used 是已被占用的端口集合；端口留空时从中避开随机挑一个。
// 这段逻辑对两种后端完全一致，所以从 Native.CreateInbound 里抽出来共用，
// 免得 3x-ui 那边再写一份走样的校验。
// 注意：Hysteria2/TUIC 在这里只做组合校验，真正能不能建由各后端
// CreateInbound 再按核心类型把关（自建 sing-box 才能建，见 native.go）。
func normalizeInboundSpec(spec NewInboundSpec, used map[int]bool) (*normalizedSpec, error) {
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto == "" {
		proto = "vless"
	}
	if !nativeProtocols[proto] {
		return nil, fmt.Errorf("不支持的协议 %q", spec.Protocol)
	}
	network := strings.ToLower(strings.TrimSpace(spec.Network))
	if network == "" {
		if isRelayProtocol(proto) {
			network = "udp"
		} else {
			network = "tcp"
		}
	}
	if !nativeNetworks[network] {
		return nil, fmt.Errorf("不支持的传输方式 %q", spec.Network)
	}
	security := strings.ToLower(strings.TrimSpace(spec.Security))
	if security == "" {
		if isRelayProtocol(proto) {
			security = "tls"
		} else {
			security = "none"
		}
	}
	if !nativeSecurities[security] {
		return nil, fmt.Errorf("不支持的安全层 %q", spec.Security)
	}
	// Hysteria2/TUIC：UDP 之上的 QUIC 传输，TLS 是协议本身的一部分，
	// 不能换成 none/REALITY，也不能再套 ws/grpc/xhttp，更不能用 Vision。
	if isRelayProtocol(proto) {
		if network != "udp" {
			return nil, fmt.Errorf("%s 只支持 UDP 传输，不支持 %s", proto, network)
		}
		if security != "tls" {
			return nil, fmt.Errorf("%s 必须用 TLS，不支持 %s", proto, security)
		}
		if spec.Vision {
			return nil, fmt.Errorf("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY")
		}
	}
	// REALITY 靠模仿 TLS 握手工作，套在 ws/grpc 这类已有自己头部的传输上没有意义，
	// Xray 也不接受这种组合
	if security == "reality" && network != "tcp" && network != "xhttp" && network != "grpc" {
		return nil, fmt.Errorf("REALITY 不支持 %s 传输", network)
	}
	// VMess 已移除，这里不再有 vmess+ws+tls 组合需要放行。

	port := spec.Port
	if port == 0 {
		p, err := freeRandomPort(used)
		if err != nil {
			return nil, err
		}
		port = p
	} else if used[port] {
		return nil, fmt.Errorf("端口 %d 已被别的入站占用", port)
	}

	path := strings.TrimSpace(spec.Path)
	if path == "" {
		switch network {
		case "ws", "httpupgrade", "xhttp":
			path = "/" + randomHex(6)
		case "grpc":
			path = randomHex(6)
		}
	}

	remark := strings.TrimSpace(spec.Remark)
	if remark == "" {
		remark = fmt.Sprintf("%s-%d", proto, port)
	}

	flow := ""
	if spec.Vision {
		if !visionCapable(proto, network, security) {
			return nil, fmt.Errorf("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY")
		}
		flow = "xtls-rprx-vision"
	}

	return &normalizedSpec{
		Protocol: proto,
		Network:  network,
		Security: security,
		Port:     port,
		Path:     path,
		Host:     strings.TrimSpace(spec.Host),
		Remark:   remark,
		Flow:     flow,
	}, nil
}
