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
	// 只有 Hysteria2 能用：Salamander 混淆口令与跳跃端口段。
	ObfsPassword string
	HopPorts     string
}

// isQUICProtocol 判断协议是不是走 QUIC/UDP 的那一类。
//
// Hysteria2 与 TUIC 都不是 TCP 流式协议：它们在 UDP 上跑 QUIC，
// 强制要求 TLS，且没有 ws/grpc/xhttp 那种“路径/Host 头”传输层。
// 这个判断是 sing-box 入站、分享链接、订阅转换共用的分水岭。
func isQUICProtocol(proto string) bool {
	return proto == "hysteria2" || proto == "tuic"
}

// normalizeInboundSpec 校验协议组合并补上默认值。
//
// used 是已被占用的端口集合；端口留空时从中避开随机挑一个。
// 这段逻辑对两种后端完全一致，所以从 Native.CreateInbound 里抽出来共用，
// 免得 3x-ui 那边再写一份走样的校验。
//
// 注意：Hysteria2/TUIC 在这里只做“组合是否合法”的校验，
// “哪个后端能跑”由各后端 CreateInbound 自己再拦：
// 自建 Xray、3x-ui、S-UI 都没有 Hy2/TUIC 服务端，只有自建 sing-box 能跑。
func normalizeInboundSpec(spec NewInboundSpec, used map[int]bool) (*normalizedSpec, error) {
	proto := strings.ToLower(strings.TrimSpace(spec.Protocol))
	if proto == "" {
		proto = "vless"
	}
	if !nativeProtocols[proto] {
		return nil, fmt.Errorf("不支持的协议 %q", spec.Protocol)
	}
	if isQUICProtocol(proto) {
		// QUIC 协议的组合是固定的，不接受 TCP/ws/grpc/REALITY/none 的混搭：
		// 留空时补成 UDP+TLS，填了别的就直接报错，别静默改成用户没要的组合。
		network := strings.ToLower(strings.TrimSpace(spec.Network))
		if network == "" {
			network = "udp"
		}
		if network != "udp" {
			return nil, fmt.Errorf("Hysteria2/TUIC 只支持 UDP 传输，不支持 %q", spec.Network)
		}
		security := strings.ToLower(strings.TrimSpace(spec.Security))
		if security == "" {
			security = "tls"
		}
		if security != "tls" {
			return nil, fmt.Errorf("Hysteria2/TUIC 必须使用 TLS，不支持 %q", spec.Security)
		}
		if spec.Vision {
			return nil, fmt.Errorf("xtls-rprx-vision 只能用于 VLESS + TCP + TLS/REALITY")
		}
		// Salamander 与端口跳跃都是 Hysteria2 专属：TUIC 的 sing-box
		// 入站没有 obfs 字段、客户端也不认 server_ports，填了只能报错，
		// 不能静默丢掉让用户以为已经生效。
		obfsPassword := strings.TrimSpace(spec.ObfsPassword)
		hopPorts := strings.TrimSpace(spec.HopPorts)
		if proto != "hysteria2" && (obfsPassword != "" || hopPorts != "") {
			return nil, fmt.Errorf("Salamander 混淆与端口跳跃只支持 Hysteria2，%s 不能用", proto)
		}
		hop, err := parseHopPorts(hopPorts)
		if err != nil {
			return nil, err
		}
		port := spec.Port
		if port == 0 {
			p, err := freeRandomPort(used)
			if err != nil {
				return nil, err
			}
			port = p
		} else if used[port] {
			return nil, fmt.Errorf("端口 %d 已被别的入站占用", port)
		} else if !udpPortAvailable(port) {
			// 手填端口不走上面的随机分配，used 里也没有系统 UDP 服务，
			// 这里直接查一次，免得 sing-box 启动时才报端口被占。
			return nil, fmt.Errorf("端口 %d 的 UDP 已被占用，Hysteria2/TUIC 无法监听", port)
		}
		for _, p := range hop {
			if p == port {
				return nil, fmt.Errorf("跳跃端口段不能包含主端口 %d", port)
			}
			if used[p] {
				return nil, fmt.Errorf("跳跃端口 %d 已被别的入站占用", p)
			}
			if !udpPortAvailable(p) {
				return nil, fmt.Errorf("跳跃端口 %d 的 UDP 已被占用", p)
			}
		}
		remark := strings.TrimSpace(spec.Remark)
		if remark == "" {
			remark = fmt.Sprintf("%s-%d", proto, port)
		}
		// QUIC 没有 ws 路径/Host 头：传进来的 Path/Host 直接丢掉，
		// 免得它们被误写进 sing-box 配置或分享链接。
		return &normalizedSpec{
			Protocol:     proto,
			Network:      network,
			Security:     security,
			Port:         port,
			Path:         "",
			Host:         "",
			Remark:       remark,
			Flow:         "",
			ObfsPassword: obfsPassword,
			HopPorts:     hopPorts,
		}, nil
	}
	if strings.TrimSpace(spec.ObfsPassword) != "" || strings.TrimSpace(spec.HopPorts) != "" {
		return nil, fmt.Errorf("Salamander 混淆与端口跳跃只支持 Hysteria2，%s 不能用", proto)
	}
	network := strings.ToLower(strings.TrimSpace(spec.Network))
	if network == "" {
		network = "tcp"
	}
	if !nativeNetworks[network] {
		return nil, fmt.Errorf("不支持的传输方式 %q", spec.Network)
	}
	security := strings.ToLower(strings.TrimSpace(spec.Security))
	if security == "" {
		security = "none"
	}
	if !nativeSecurities[security] {
		return nil, fmt.Errorf("不支持的安全层 %q", spec.Security)
	}
	// REALITY 靠模仿 TLS 握手工作，套在 ws/grpc 这类已有自己头部的传输上没有意义，
	// Xray 也不接受这种组合
	if security == "reality" && network != "tcp" && network != "xhttp" && network != "grpc" {
		return nil, fmt.Errorf("REALITY 不支持 %s 传输", network)
	}
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
