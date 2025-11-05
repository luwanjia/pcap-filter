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
	Proto string // 传输层协议（tcp/udp/icmp）
}

// 会话信息结构体（增加负载提取状态）
type Session struct {
	Key              SessionKey
	AppProto         string           // 应用层协议
	RegexMatch       string           // 正则命中内容
	Packets          []gopacket.Packet // 会话数据包
	TCPFlowCache     []byte           // 完整TCP流缓存
	hasValidPayload  bool             // 是否提取到有效应用层负载
}

// 全局变量
var (
	input         string // 输入pcap文件（必填）
	proto         string // 传输层协议过滤
	app           string // 应用层协议过滤
	sip           string // 源IP过滤
	sport         uint   // 源端口过滤
	dip           string // 目的IP过滤
	dport         uint   // 目的端口过滤
	regexStr      string // 正则过滤
	outputDir     string // 输出目录
	customFeature string // 自定义协议特征
	ignoreCase    bool   // 特征匹配忽略大小写

	sessions = make(map[SessionKey]*Session) // 会话存储映射
	// HTTP正则特征（容错性极强：允许开头空白、GET后多空格、忽略大小写）
	httpRegex = regexp.MustCompile(`(?i)^\s*(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+|^\s*HTTP/\d\.\d\s+`)
)

func main() {
	parseFlags()

	if err := validateParams(); err != nil {
		fmt.Printf("参数错误：%v\n", err)
		printUsage()
		os.Exit(1)
	}

	fmt.Printf("正在解析pcap文件：%s（HTTP负载容错+正则强匹配）\n", input)
	if err := processPcap(); err != nil {
		fmt.Printf("解析失败：%v\n", err)
		os.Exit(1)
	}

	identifyAppProtocols() // 核心：强容错识别

	fmt.Printf("解析完成，共找到 %d 个符合条件的会话\n", len(sessions))
	if err := outputResults(); err != nil {
		fmt.Printf("输出失败：%v\n", err)
		os.Exit(1)
	}

	fmt.Println("操作完成！")
}

// 解析命令行参数
func parseFlags() {
	fmt.Println("pcap-filter - HTTP强容错识别版（解决负载提取问题）")
	fmt.Println("=====================================")

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.StringVar(&input, "input", "", "输入pcap文件路径（必填）")
	flagSet.StringVar(&proto, "proto", "", "传输层协议过滤（可选：tcp/udp/icmp）")
	flagSet.StringVar(&app, "app", "", "应用层协议过滤（可选：http/https/tcp-text等）")
	flagSet.StringVar(&sip, "sip", "", "源IP过滤（可选）")
	flagSet.UintVar(&sport, "sport", 0, "源端口过滤（可选，1-65535）")
	flagSet.StringVar(&dip, "dip", "", "目的IP过滤（可选）")
	flagSet.UintVar(&dport, "dport", 0, "目的端口过滤（可选，1-65535）")
	flagSet.StringVar(&regexStr, "regex", "", "正则过滤（可选）")
	flagSet.StringVar(&outputDir, "output", "", "输出目录（可选）")
	flagSet.StringVar(&customFeature, "custom-feature", "", "自定义协议特征（可选）")
	flagSet.BoolVar(&ignoreCase, "ignore-case", true, "特征匹配忽略大小写（默认开启）")

	flagSet.Usage = printUsage
	if len(os.Args) == 1 {
		printUsage()
		os.Exit(0)
	}

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		fmt.Printf("参数解析错误：%v\n", err)
		os.Exit(1)
	}
}

// 参数校验
func validateParams() error {
	if input == "" {
		return errors.New("必须指定 -input 参数")
	}
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("输入文件不存在：%s", input)
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
		return errors.New("app参数支持：http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload")
	}

	if sport != 0 && (sport < 1 || sport > 65535) {
		return errors.New("sport必须是 1-65535 之间的整数")
	}
	if dport != 0 && (dport < 1 || dport > 65535) {
		return errors.New("dport必须是 1-65535 之间的整数")
	}

	if sip != "" && net.ParseIP(sip) == nil {
		return fmt.Errorf("非法源IP：%s", sip)
	}
	if dip != "" && net.ParseIP(dip) == nil {
		return fmt.Errorf("非法目的IP：%s", dip)
	}

	if regexStr != "" {
		if _, err := regexp.Compile(regexStr); err != nil {
			return fmt.Errorf("非法正则表达式：%s（%v）", regexStr, err)
		}
	}

	if outputDir != "" {
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("创建输出目录失败：%v", err)
			}
		}
	}

	return nil
}

// 解析pcap（修复TCP负载提取，标记有效负载状态）
func processPcap() error {
	handle, err := pcap.OpenOffline(input)
	if err != nil {
		return fmt.Errorf("打开pcap失败：%v", err)
	}
	defer handle.Close()

	// 修复解码顺序：确保TCP层在IP层之后，优先解码TCP
	decoder := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&layers.Ethernet{}, // 链路层
		&layers.IPv4{},      // IP层（优先IPv4，适配大部分场景）
		&layers.IPv6{},
		&layers.TCP{},       // TCP层（紧跟IP层，确保能正确提取）
		&layers.UDP{},
		&layers.ICMPv4{},
		&layers.ICMPv6{},
	)
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 强制解码所有层，忽略解码错误（避免漏解TCP层）
		_ = decoder.DecodeLayers(packet.Data(), &decodedLayers)

		// 手动提取TCP层（避免decoder顺序问题导致漏解）
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue // 非TCP包，跳过
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			continue
		}

		// 提取IP层（手动提取，确保IP信息正确）
		var pktSIP, pktDIP string
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ip4Layer != nil {
			ip4 := ip4Layer.(*layers.IPv4)
			pktSIP = ip4.SrcIP.String()
			pktDIP = ip4.DstIP.String()
		} else {
			ip6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ip6Layer == nil {
				continue // 无IP层，跳过
			}
			ip6 := ip6Layer.(*layers.IPv6)
			pktSIP = ip6.SrcIP.String()
			pktDIP = ip6.DstIP.String()
		}

		// 提取TCP端口和应用层负载（核心修复：直接从TCP层拿payload）
		pktSPort := uint(tcp.SrcPort)
		pktDPort := uint(tcp.DstPort)
		payload := tcp.Payload // 直接用tcp.Payload，避免LayerPayload()的潜在问题
		transProto := "tcp"

		// 应用基础过滤
		if !applyBasicFilters(pktSIP, pktDIP, pktSPort, pktDPort, transProto) {
			continue
		}

		// 添加到会话，标记是否有有效负载
		addToSessionWithPayloadCheck(pktSIP, pktDIP, pktSPort, pktDPort, transProto, payload, len(payload) > 0, packet)
	}

	return nil
}

// 基础过滤
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

// 添加会话+标记有效负载状态
func addToSessionWithPayloadCheck(pktSIP, pktDIP string, pktSPort, pktDPort uint, transProto string, payload []byte, hasValidPayload bool, packet gopacket.Packet) {
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
			AppProto:         "tcp-no-payload", // 默认：无负载
			RegexMatch:       "",
			Packets:          make([]gopacket.Packet, 0),
			TCPFlowCache:     make([]byte, 0),
			hasValidPayload:  false,
		}
	}

	session := sessions[key]
	// 合并负载（仅保留非空负载，避免垃圾数据）
	if len(payload) > 0 {
		session.TCPFlowCache = append(session.TCPFlowCache, payload...)
		session.hasValidPayload = true // 标记有有效负载
	}
	session.Packets = append(session.Packets, packet)
}

// 协议识别（强容错：正则匹配+负载状态判断）
func identifyAppProtocols() {
	for _, session := range sessions {
		// 1. 先处理无负载的会话
		if !session.hasValidPayload || len(session.TCPFlowCache) == 0 {
			session.AppProto = "tcp-no-payload"
			continue
		}

		fullPayload := session.TCPFlowCache
		payloadStr := string(fullPayload)

		// 2. 强容错HTTP识别（正则匹配，忽略大小写、开头空白、多空格）
		if httpRegex.MatchString(payloadStr) {
			session.AppProto = "http"
			// 正则过滤（针对HTTP会话）
			if regexStr != "" {
				match := regexp.MustCompile(regexStr).Find(fullPayload)
				if match == nil {
					delete(sessions, session.Key)
				} else {
					session.RegexMatch = sanitizeFilename(string(match[:min(len(match), 32)]))
				}
			}
			continue
		}

		// 3. 匹配其他通用协议（非HTTP）
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
		if identified {
			// 其他协议的正则过滤
			if regexStr != "" {
				match := regexp.MustCompile(regexStr).Find(fullPayload)
				if match == nil {
					delete(sessions, session.Key)
				} else {
					session.RegexMatch = sanitizeFilename(string(match[:min(len(match), 32)]))
				}
			}
			continue
		}

		// 4. 最后判断文本/二进制（HTTP识别失败后）
		if isTextPayload(fullPayload) {
			session.AppProto = "tcp-text"
		} else {
			session.AppProto = "tcp-binary"
		}

		// 5. 文本/二进制的正则过滤
		if regexStr != "" {
			match := regexp.MustCompile(regexStr).Find(fullPayload)
			if match == nil {
				delete(sessions, session.Key)
			} else {
				session.RegexMatch = sanitizeFilename(string(match[:min(len(match), 32)]))
			}
		}

		// 6. 应用层过滤
		if app != "" && !strings.EqualFold(session.AppProto, app) {
			delete(sessions, session.Key)
		}
	}
}

// 文本判断（严格但合理，避免误判）
func isTextPayload(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	// 允许：可见ASCII（32-126）+ 换行（10）+ 回车（13）+ 制表符（9）+ 水平制表符（11）
	// 排除不可见控制字符（如\x00-\x08、\x0b等），避免二进制误判为文本
	for _, b := range payload {
		if !(b >= 32 && b <= 126 || b == 9 || b == 10 || b == 11 || b == 13) {
			return false
		}
	}
	// 文本不能全是空白字符（避免空负载误判）
	nonSpaceCount := 0
	for _, b := range payload {
		if b != 32 && b != 9 && b != 10 && b != 11 && b != 13 {
			nonSpaceCount++
			break
		}
	}
	return nonSpaceCount > 0
}

// 清理文件名
func sanitizeFilename(name string) string {
	reg := regexp.MustCompile(`[\\/:*?"<>|]`)
	return reg.ReplaceAllString(name, "_")
}

// 输出结果
func outputResults() error {
	if outputDir == "" {
		fmt.Println("\n会话详情：")
		fmt.Println("----------------------------------------------------------------------")
		fmt.Printf("%-8s %-16s %-25s %-25s %s\n", "传输层", "应用层（强容错）", "源地址:端口", "目的地址:端口", "正则命中")
		fmt.Println("----------------------------------------------------------------------")
		for _, session := range sessions {
			src := fmt.Sprintf("%s:%d", session.Key.SIP, session.Key.SPort)
			dst := fmt.Sprintf("%s:%d", session.Key.DIP, session.Key.DPort)
			regex := session.RegexMatch
			if regex == "" {
				regex = "-"
			}
			fmt.Printf("%-8s %-16s %-25s %-25s %s\n",
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
			return fmt.Errorf("创建文件失败：%s（%v）", filePath, err)
		}
		defer file.Close()

		linkType := session.Packets[0].LinkLayer().LayerType()
		writer := pcapgo.NewWriter(file)
		if err := writer.WriteFileHeader(65536, layers.LinkType(linkType)); err != nil {
			return fmt.Errorf("写入文件头失败：%s（%v）", filePath, err)
		}

		for _, pkt := range session.Packets {
			captureInfo := gopacket.CaptureInfo{
				Timestamp:      pkt.Metadata().Timestamp,
				CaptureLength:  len(pkt.Data()),
				Length:         len(pkt.Data()),
				InterfaceIndex: 0,
			}
			if err := writer.WritePacket(captureInfo, pkt.Data()); err != nil {
				return fmt.Errorf("写入数据包失败：%s（%v）", filePath, err)
			}
		}

		fmt.Printf("已保存会话：%s（协议：%s）\n", filePath, session.AppProto)
	}

	return nil
}

// 打印使用说明（针对负载提取问题）
func printUsage() {
	fmt.Println(`
使用语法：
  pcap-filter [参数]

核心修复：
  1. 手动提取TCP层和payload（解决decoder顺序导致的负载提取失败）
  2. 正则强匹配HTTP：允许开头空白、GET后多空格、忽略大小写
  3. 区分“无负载”和“二进制”，避免空负载误判为二进制

必用命令（针对你的HTTP场景）：
  1. 强制提取所有HTTP会话（不管端口/空格/大小写）：
     pcap-filter -input ../20251030200103_ip1_218.207.91.83.pcap -app http

  2. 查看所有TCP会话（区分HTTP/文本/二进制/无负载）：
     pcap-filter -input ../20251030200103_ip1_218.207.91.83.pcap -proto tcp

  3. 提取含GET请求的HTTP会话：
     pcap-filter -input ../20251030200103_ip1_218.207.91.83.pcap -app http -regex "(?i)GET\s+"
`)
}

// 辅助函数：取最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}