package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// 会话唯一标识
type SessionKey struct {
	SIP   string // 源IP
	SPort uint   // 源端口
	DIP   string // 目的IP
	DPort uint   // 目的端口
	Proto string // 传输层协议 (tcp/udp/icmp)
}

// 会话信息结构体
type Session struct {
	Key              SessionKey
	AppProto         string           // 应用层协议
	RegexMatch       string           // 正则命中内容
	Packets          []gopacket.Packet // 会话数据包
	TCPFlowCache     []byte           // TCP流缓存
	hasValidPayload  bool             // 是否含有效应用层负载
}

// 全局变量
var (
	input         string // 输入pcap文件路径
	proto         string // 传输层协议过滤 (tcp/udp/icmp)
	app           string // 应用层协议过滤
	sip           string // 源IP过滤
	sport         uint   // 源端口过滤
	dip           string // 目的IP过滤
	dport         uint   // 目的端口过滤
	regexStr      string // 正则过滤表达式
	regexInvert   bool   // 正则取反开关
	outputDir     string // 输出目录路径
	customFeature string // 自定义协议特征
	ignoreCase    bool   // 特征匹配忽略大小写

	sessions         = make(map[SessionKey]*Session) // 会话存储映射
	originalLinkType layers.LinkType                 // 原始PCAP文件的链路类型
	httpRegex        = regexp.MustCompile(`(?i)^\s*(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+|^\s*HTTP/\d\.\d\s+`)
)

func main() {
	parseFlags()

	if err := validateParams(); err != nil {
		fmt.Printf("参数错误: %v\n", err)
		printUsage()
		os.Exit(1)
	}

	fmt.Printf("正在解析pcap文件: %s\n", input)
	if err := processPcap(); err != nil {
		fmt.Printf("解析失败: %v\n", err)
		os.Exit(1)
	}

	// 应用层协议识别 + 初步协议过滤
	identifyAppProtocols()

	// -------------------------- 核心统计与过滤 --------------------------
	originalTotal := len(sessions) // 1. 原始解析会话总数（基础过滤后）
	filteredSessions := make(map[SessionKey]*Session)
	protoCount := make(map[string]int) // 按应用层协议分布

	for key, session := range sessions {
		// 过滤逻辑：根据 regexInvert 动态判断是否保留
		hit := true

		if regexStr != "" {
			if regexInvert {
				// 取反模式：正则命中 → 不保留（保留未命中的）
				if session.RegexMatch != "" {
					hit = false
				}
			} else {
				// 正向模式（默认）：正则未命中 → 不保留（保留命中的）
				if session.RegexMatch == "" {
					hit = false
				}
			}
		}

		// 命中则保留并统计
		if hit {
			filteredSessions[key] = session
			protoCount[session.AppProto]++
		}
	}

	// 更新为过滤后结果
	sessions = filteredSessions
	filteredTotal := len(sessions) // 2. 过滤后保留会话数
	// ------------------------------------------------------------------------

	fmt.Printf("解析完成，原始解析会话总数: %d, 过滤后保留会话数: %d\n", originalTotal, filteredTotal)

	if err := outputResults(); err != nil {
		fmt.Printf("输出失败: %v\n", err)
		os.Exit(1)
	}

	// -------------------------- 简化统计信息 --------------------------
	fmt.Println("\n=================== 会话统计 ===================")
	fmt.Printf("1. 原始解析会话总数：%d\n", originalTotal)
	fmt.Printf("2. 过滤后保留会话数：%d\n", filteredTotal)
	fmt.Println("3. 保留会话协议分布：")
	for p, c := range protoCount {
		fmt.Printf("   - %-12s：%d 个\n", p, c)
	}
	fmt.Println("===============================================")
	// ------------------------------------------------------------------------

	fmt.Println("操作完成！")
}

// 解析命令行参数
func parseFlags() {
	fmt.Println("PCAP会话信息过滤工具")
	fmt.Println("====================")

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.StringVar(&input, "input", "", "输入pcap文件路径 (必填)")
	flagSet.StringVar(&proto, "proto", "", "传输层协议过滤 (可选: tcp/udp/icmp)")
	flagSet.StringVar(&app, "app", "", "应用层协议过滤 (可选: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload)")
	flagSet.StringVar(&sip, "sip", "", "源IP过滤 (可选，支持IPv4/IPv6)")
	flagSet.UintVar(&sport, "sport", 0, "源端口过滤 (可选，范围: 1-65535)")
	flagSet.StringVar(&dip, "dip", "", "目的IP过滤 (可选，支持IPv4/IPv6)")
	flagSet.UintVar(&dport, "dport", 0, "目的端口过滤 (可选，范围: 1-65535)")
	flagSet.StringVar(&regexStr, "regex", "", "正则过滤表达式 (可选，匹配应用层数据)")
	flagSet.BoolVar(&regexInvert, "regex-invert", false, "正则取反匹配 (可选，默认: false，true=保留未命中正则的会话)")
	flagSet.StringVar(&outputDir, "output", "", "输出目录路径 (可选，不指定则仅打印结果)")
	flagSet.StringVar(&customFeature, "custom-feature", "", "自定义协议特征 (可选，匹配应用层数据)")
	flagSet.BoolVar(&ignoreCase, "ignore-case", true, "特征匹配忽略大小写 (可选，默认: true)")

	flagSet.Usage = printUsage
	if len(os.Args) == 1 {
		printUsage()
		os.Exit(0)
	}

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		fmt.Printf("参数解析错误: %v\n", err)
		os.Exit(1)
	}
}

// 参数校验
func validateParams() error {
	if input == "" {
		return errors.New("必须通过 -input 参数指定pcap文件路径")
	}
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("输入文件不存在: %s", input)
	}

	supportedProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "": true}
	if !supportedProtos[strings.ToLower(proto)] {
		return errors.New("proto参数仅支持 tcp/udp/icmp")
	}

	supportedApps := map[string]bool{
		"http": true, "https": true, "ssh": true, "mysql": true, "redis": true,
		"tcp-text": true, "tcp-binary": true, "tcp-no-payload": true, "": true,
	}
	if !supportedApps[strings.ToLower(app)] {
		return errors.New("app参数支持: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload")
	}

	if sport != 0 && (sport < 1 || sport > 65535) {
		return errors.New("sport参数必须是 1-65535 之间的整数")
	}
	if dport != 0 && (dport < 1 || dport > 65535) {
		return errors.New("dport参数必须是 1-65535 之间的整数")
	}

	if sip != "" && net.ParseIP(sip) == nil {
		return fmt.Errorf("非法源IP地址: %s", sip)
	}
	if dip != "" && net.ParseIP(dip) == nil {
		return fmt.Errorf("非法目的IP地址: %s", dip)
	}

	if regexStr != "" {
		if _, err := regexp.Compile(regexStr); err != nil {
			return fmt.Errorf("非法正则表达式: %s (错误: %v)", regexStr, err)
		}
	}

	if outputDir != "" {
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("创建输出目录失败: %v", err)
			}
		}
	}

	return nil
}

// 解析pcap文件
func processPcap() error {
	handle, err := pcap.OpenOffline(input)
	if err != nil {
		return fmt.Errorf("打开pcap文件失败: %v", err)
	}
	defer handle.Close()

	originalLinkType = handle.LinkType()

	decoder := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.IPv6{},
		&layers.TCP{},
		&layers.UDP{},
		&layers.ICMPv4{},
		&layers.ICMPv6{},
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, originalLinkType)
	for packet := range packetSource.Packets() {
		_ = decoder.DecodeLayers(packet.Data(), &decodedLayers)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			continue
		}

		var pktSIP, pktDIP string
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			pktSIP = ip4.SrcIP.String()
			pktDIP = ip4.DstIP.String()
		} else {
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ip6Layer == nil {
				continue
			}
			ip6 := ip6Layer.(*layers.IPv6)
			pktSIP = ip6.SrcIP.String()
			pktDIP = ip6.DstIP.String()
		}

		pktSPort := uint(tcp.SrcPort)
		pktDPort := uint(tcp.DstPort)
		payload := tcp.Payload
		transProto := "tcp"

		if !applyBasicFilters(pktSIP, pktDIP, pktSPort, pktDPort, transProto) {
			continue
		}

		addToSession(pktSIP, pktDIP, pktSPort, pktDPort, transProto, payload, len(payload) > 0, packet)
	}

	return nil
}

// 基础过滤逻辑
func applyBasicFilters(pktSIP, pktDIP string, pktSPort, pktDPort uint, transProto string) bool {
	if proto != "" && !strings.EqualFold(transProto, proto) {
		return false
	}
	if sip != "" && !strings.EqualFold(pktSIP, sip) {
		return false
	}
	if sport != 0 && pktSPort != sport {
		return false
	}
	if dip != "" && !strings.EqualFold(pktDIP, dip) {
		return false
	}
	if dport != 0 && pktDPort != dport {
		return false
	}
	return true
}

// 添加会话
func addToSession(pktSIP, pktDIP string, pktSPort, pktDPort uint, transProto string, payload []byte, hasValidPayload bool, packet gopacket.Packet) {
	key := SessionKey{
		SIP:   pktSIP,
		SPort: pktSPort,
		DIP:   pktDIP,
		DPort: pktDPort,
		Proto: transProto,
	}

	if _, exists := sessions[key]; !exists {
		sessions[key] = &Session{
			Key:              key,
			AppProto:         "tcp-no-payload",
			RegexMatch:       "",
			Packets:          make([]gopacket.Packet, 0),
			TCPFlowCache:     make([]byte, 0),
			hasValidPayload:  false,
		}
	}

	session := sessions[key]
	if len(payload) > 0 {
		session.TCPFlowCache = append(session.TCPFlowCache, payload...)
		session.hasValidPayload = true
	}
	session.Packets = append(session.Packets, packet)
}

// 应用层协议识别 + 协议过滤
func identifyAppProtocols() {
	validSessions := make(map[SessionKey]*Session)

	for _, session := range sessions {
		// 协议识别
		if !session.hasValidPayload || len(session.TCPFlowCache) == 0 {
			session.AppProto = "tcp-no-payload"
		} else {
			fullPayload := session.TCPFlowCache
			payloadStr := string(fullPayload)

			if httpRegex.MatchString(payloadStr) {
				session.AppProto = "http"
			} else {
				otherProtos := map[string][]string{
					"https": {"\x16\x03\x01", "\x16\x03\x02", "\x16\x03\x03", "\x16\x03\x04"},
					"ssh":   {"SSH-"},
					"mysql": {"\x0aMySQL", "\x0amariadb"},
					"redis": {"+OK", "-ERR", ":1", "$0", "*0"},
				}
				identified := false
				for protoName, features := range otherProtos {
					for _, feat := range features {
						if ignoreCase {
							if strings.Contains(strings.ToLower(payloadStr), strings.ToLower(feat)) {
								session.AppProto = protoName
								identified = true
								break
							}
						} else {
							if strings.Contains(payloadStr, feat) {
								session.AppProto = protoName
								identified = true
								break
							}
						}
					}
					if identified {
						break
					}
				}
				if !identified {
					if isTextPayload(fullPayload) {
						session.AppProto = "tcp-text"
					} else {
						session.AppProto = "tcp-binary"
					}
				}
			}

			// 正则匹配
			if regexStr != "" {
				match := regexp.MustCompile(regexStr).Find(session.TCPFlowCache)
				if match != nil {
					session.RegexMatch = sanitizeFilename(string(match[:min(len(match), 32)]))
				} else {
					session.RegexMatch = ""
				}
			}
		}

		// 协议过滤（指定-app则保留匹配项）
		if app == "" || strings.EqualFold(session.AppProto, app) {
			validSessions[session.Key] = session
		}
	}

	sessions = validSessions
}

// 文本负载判断
func isTextPayload(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	for _, b := range payload {
		if !(b >= 32 && b <= 126 || b == 9 || b == 10 || b == 11 || b == 13) {
			return false
		}
	}
	nonSpaceCount := 0
	for _, b := range payload {
		if b != 32 && b != 9 && b != 10 && b != 11 && b != 13 {
			nonSpaceCount++
			break
		}
	}
	return nonSpaceCount > 0
}

// 清理文件名非法字符
func sanitizeFilename(name string) string {
	reg := regexp.MustCompile(`[\\/:*?"<>|]`)
	return reg.ReplaceAllString(name, "_")
}

// 结果输出
func outputResults() error {
	if len(sessions) == 0 {
		fmt.Println("\n无符合条件的会话可输出")
		return nil
	}

	if outputDir == "" {
		fmt.Println("\n会话详情: ")
		fmt.Println("--------------------------------------------------------------------------------------------------")
		fmt.Printf("%-5s %-7s %-20s %-20s %s\n", "传输层", "应用层协议", "源地址:端口", "目的地址:端口", "正则命中")
		fmt.Println("--------------------------------------------------------------------------------------------------")
		for _, session := range sessions {
			src := fmt.Sprintf("%s:%d", session.Key.SIP, session.Key.SPort)
			dst := fmt.Sprintf("%s:%d", session.Key.DIP, session.Key.DPort)
			regex := session.RegexMatch
			if regex == "" {
				regex = "-"
			}
			fmt.Printf("%-8s %-12s %-25s %-25s %s\n",
				session.Key.Proto,
				session.AppProto,
				src,
				dst,
				regex,
			)
		}
		return nil
	}

	for _, session := range sessions {
		filename := fmt.Sprintf("%s_%d_%s_%d_%s",
			session.Key.SIP,
			session.Key.SPort,
			session.Key.DIP,
			session.Key.DPort,
			session.AppProto,
		)
		if session.RegexMatch != "" {
			filename += "_" + session.RegexMatch
		}
		filename += ".pcap"
		filePath := filepath.Join(outputDir, filename)

		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("创建文件失败: %s (错误: %v)", filePath, err)
		}
		defer file.Close()

		writer := pcapgo.NewWriter(file)
		snapLen := uint32(65536)
		if err := writer.WriteFileHeader(snapLen, originalLinkType); err != nil {
			return fmt.Errorf("写入文件头失败: %s (错误: %v)", filePath, err)
		}

		for _, pkt := range session.Packets {
			pktData := pkt.Data()
			if len(pktData) == 0 {
				continue
			}

			meta := pkt.Metadata()
			captureInfo := gopacket.CaptureInfo{
				Timestamp:      meta.Timestamp,
				CaptureLength:  len(pktData),
				Length:         len(pktData),
				InterfaceIndex: meta.InterfaceIndex,
			}

			if err := writer.WritePacket(captureInfo, pktData); err != nil {
				return fmt.Errorf("写入数据包失败: %s (错误: %v)", filePath, err)
			}
		}

		fmt.Printf("已保存会话文件: %s (%d pkts)\n", filePath, len(session.Packets))
	}

	return nil
}

// 打印使用说明
func printUsage() {
	fmt.Println(`
使用语法: 
  pcap-filter [参数]

参数说明: 
  -input          string   输入pcap文件路径 (必填)
  -proto          string   传输层协议过滤 (可选: tcp/udp/icmp)
  -app            string   应用层协议过滤 (可选: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload)
  -sip            string   源IP过滤 (可选，支持IPv4/IPv6)
  -sport          uint     源端口过滤 (可选，范围: 1-65535)
  -dip            string   目的IP过滤 (可选，支持IPv4/IPv6)
  -dport          uint     目的端口过滤 (可选，范围: 1-65535)
  -regex          string   正则过滤表达式 (可选，匹配应用层数据)
  -regex-invert   bool     正则取反匹配 (可选，默认: false，true=保留未命中正则的会话)
  -output         string   输出目录路径 (可选，不指定则仅打印结果)
  -custom-feature string   自定义协议特征 (可选，匹配应用层数据)
  -ignore-case    bool     特征匹配忽略大小写 (可选，默认: true)

使用样例: 
  1. 正向匹配：保留含 BAS_ID=.{16} 的HTTP会话
     pcap-filter -input traffic.pcap -app http -regex "BAS_ID=.{16}"

  2. 反向匹配：保留不含 BAS_ID=.{16} 的HTTP会话（新增参数）
     pcap-filter -input traffic.pcap -app http -regex "BAS_ID=.{16}" -regex-invert

  3. 反向匹配+输出文件：保留不含目标正则的会话并保存
     pcap-filter -input traffic.pcap -app http -regex "BAS_ID=.{16}" -regex-invert -output ./non_bas_sessions
`)
}

// 取最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}