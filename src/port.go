package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// 随机端口的取值范围，落在 IANA 动态端口区间内，避开常见服务。
const (
	randPortMin = 20000
	randPortMax = 60000
)

// freeRandomPort 随机挑一个当前空闲的端口。
//
// taken 里的端口会被跳过，用于避开本进程已经分配但还没真正监听的端口。
// 实际可用性以能否 bind 为准，这样不会和系统上其他进程抢。
// TCP 与 UDP 的端口号本是两个命名空间，但这里同时检查两者：
// Hysteria2/TUIC 只用 UDP，随机到一个已被 UDP 服务占用的端口会直接起不来，
// 而同一个端口号同时出现在 TCP 入站和 QUIC 入站里也容易让防火墙配置出错。
func freeRandomPort(taken map[int]bool) (int, error) {
	for i := 0; i < 200; i++ {
		port := randPortMin + rand.Intn(randPortMax-randPortMin)
		if taken[port] {
			continue
		}
		if portAvailable(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("找不到可用端口（已尝试 200 次）")
}

// portAvailable 通过尝试监听来判断端口是否真的空闲。
func portAvailable(port int) bool {
	for _, family := range []struct{ network, host string }{{"tcp4", "0.0.0.0"}, {"tcp6", "::"}} {
		ln, err := net.Listen(family.network, net.JoinHostPort(family.host, fmt.Sprint(port)))
		if err != nil {
			if family.network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
				continue
			}
			return false
		}
		ln.Close()
	}
	return udpPortAvailable(port)
}

// parseHopPorts 解析 Hysteria2 跳跃端口段，例如 "30010-30020"、
// "30010,30012"、"30010-30012,30015"。返回展开后的端口列表。
// 跳跃段是主端口之外的附加监听端口，sing-box 服务端不能直接监听
// 一个段（1.14.3 实测：listen_port_range、services 里的 port_hopping
// 都会被 check 拒绝），所以 y-gate 会为每个跳跃端口再生成一个
// 同配置的影子入站；段里端口太多会生成一堆入站，这里上限 32 个。
func parseHopPorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("跳跃端口段里有空项")
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("跳跃端口段 %q 无效，应写成 起始-结束，如 30010-30020", token)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(token)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("跳跃端口 %q 无效", token)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
		if len(ports) > 32 {
			return nil, fmt.Errorf("跳跃端口最多 32 个，%q 超出了", s)
		}
	}
	sort.Ints(ports)
	return ports, nil
}

// hopPortsString 把展开的端口列表压回一段字符串：连续的写成段，
// 不连续的用逗号分隔。克隆到出口时用它生成新的、不冲突的段。
func hopPortsString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := []string{}
	start, prev := ports[0], ports[0]
	flush := func() {
		if start == prev {
			parts = append(parts, strconv.Itoa(start))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", start, prev))
		}
	}
	for _, p := range ports[1:] {
		if p == prev+1 {
			prev = p
			continue
		}
		flush()
		start, prev = p, p
	}
	flush()
	return strings.Join(parts, ",")
}

// allocateHopRange 在随机端口区间里找一段连续、当前 UDP 空闲的
// 跳跃端口。模板克隆到多个出口时不能照抄同一段（会撞端口），
// 每个克隆出口都用这个函数单独分配一段。
func allocateHopRange(taken map[int]bool, count int) ([]int, error) {
	if count <= 0 {
		return nil, nil
	}
	for i := 0; i < 100; i++ {
		start := randPortMin + rand.Intn(randPortMax-randPortMin-count)
		ports := make([]int, count)
		ok := true
		for j := range ports {
			p := start + j
			if taken[p] || !udpPortAvailable(p) {
				ok = false
				break
			}
			ports[j] = p
		}
		if ok {
			return ports, nil
		}
	}
	return nil, fmt.Errorf("找不到 %d 个连续的空闲 UDP 跳跃端口", count)
}

// udpPortAvailable 只查 UDP：QUIC 入站只监听 UDP，TCP 占用不该拦它。
func udpPortAvailable(port int) bool {
	for _, family := range []struct{ network, host string }{{"udp4", "0.0.0.0"}, {"udp6", "::"}} {
		pc, err := net.ListenPacket(family.network, net.JoinHostPort(family.host, fmt.Sprint(port)))
		if err != nil {
			if family.network == "udp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
				continue
			}
			return false
		}
		pc.Close()
	}
	return true
}
