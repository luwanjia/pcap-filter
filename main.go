package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// SessionKey 会话唯一标识(支持双向流量归一化)
type SessionKey struct {
	SrcAddr string // 归一化源地址(IP:Port)
	DstAddr string // 归一化目的地址(IP:Port)
	Proto   string // 传输层协议 (tcp/udp/icmp)
}

// Session 会话信息结构体
type Session struct {
	Key             SessionKey
	AppProto        string           // 应用层协议
	RegexMatch      string           // 正则命中内容
	Packets         []gopacket.Packet // 会话数据包
	TCPFlowCache    []byte           // TCP双向流合并缓存
	hasValidPayload bool             // 是否含有效应用层负载
}

// 全局变量定义
var (
	input         string // 输入pcap文件路径
	proto         string // 传输层协议过滤 (tcp/udp/icmp)
	app           string // 应用层协议过滤
	sip           string // 源IP过滤(双向匹配)
	sport         uint   // 源端口过滤(双向匹配)
	dip           string // 目的IP过滤(双向匹配)
	dport         uint   // 目的端口过滤(双向匹配)
	regexStr      string // 正则过滤表达式
	regexInvert   bool   // 正则取反开关
	outputDir     string // 输出目录路径
	customFeature string // 自定义协议特征
	ignoreCase    bool   // 特征匹配忽略大小写

	sessions         = make(map[SessionKey]*Session) // 会话存储映射
	originalLinkType layers.LinkType                 // 原始PCAP链路类型
	httpRegex        = regexp.MustCompile(`(?i)^\s*(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+|^\s*HTTP/\d\.\d\s+`)
	redisRegex       = regexp.MustCompile(`^(\+OK|\-ERR|\:[\d]+|\$[\d]+|\*[\d]+)\r\n`) // Redis精准匹配正则
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

	identifyAppProtocols() // 应用层协议识别+初步过滤

	// 核心统计与过滤
	originalTotal := len(sessions)
	filteredSessions := make(map[SessionKey]*Session)
	protoCount := make(map[string]int)

	// 有序遍历确保结果一致
	var sortedKeys []SessionKey
	for key := range sessions {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i].SrcAddr+sortedKeys[i].DstAddr < sortedKeys[j].SrcAddr+sortedKeys[j].DstAddr
	})

	for _, key := range sortedKeys {
		session := sessions[key]
		hit := true

		// 正则过滤逻辑
		if regexStr != "" {
			if regexInvert {
				if session.RegexMatch != "" {
					hit = false
				}
			} else {
				if session.RegexMatch == "" {
					hit = false
				}
			}
		}

		if hit {
			filteredSessions[key] = session
			protoCount[session.AppProto]++
		}
	}

	sessions = filteredSessions
	filteredTotal := len(sessions)
	fmt.Printf("解析完成, 原始会话数: %d, 过滤后会话数: %d\n", originalTotal, filteredTotal)

	if err := outputResults(); err != nil {
		fmt.Printf("输出失败: %v\n", err)
		os.Exit(1)
	}

	// 统计信息输出
	fmt.Println("\n=================== 会话统计 ===================")
	fmt.Printf("1. 原始解析会话总数: %d\n", originalTotal)
	fmt.Printf("2. 过滤后保留会话数: %d\n", filteredTotal)
	fmt.Println("3. 保留会话协议分布: ")
	var protoNames []string
	for p := range protoCount {
		protoNames = append(protoNames, p)
	}
	sort.Strings(protoNames)
	for _, p := range protoNames {
		fmt.Printf("   - %-12s: %d 个\n", p, protoCount[p])
	}
	fmt.Println("===============================================")

	fmt.Println("操作完成！")
}

// parseFlags 解析命令行参数
func parseFlags() {
	fmt.Println("PCAP会话过滤工具")
	fmt.Println("====================")

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.StringVar(&input, "input", "", "输入pcap文件路径 (必填)")
	flagSet.StringVar(&proto, "proto", "", "传输层协议过滤 (可选: tcp/udp/icmp)")
	flagSet.StringVar(&app, "app", "", "应用层协议过滤 (可选: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload)")
	flagSet.StringVar(&sip, "sip", "", "源IP过滤 (可选, 双向匹配)")
	flagSet.UintVar(&sport, "sport", 0, "源端口过滤 (可选, 1-65535, 双向匹配)")
	flagSet.StringVar(&dip, "dip", "", "目的IP过滤 (可选, 双向匹配)")
	flagSet.UintVar(&dport, "dport", 0, "目的端口过滤 (可选, 1-65535, 双向匹配)")
	flagSet.StringVar(&regexStr, "regex", "", "正则过滤表达式 (可选)")
	flagSet.BoolVar(&regexInvert, "regex-invert", false, "正则取反 (默认: false)")
	flagSet.StringVar(&outputDir, "output", "", "输出目录 (可选)")
	flagSet.StringVar(&customFeature, "custom-feature", "", "自定义协议特征 (可选)")
	flagSet.BoolVar(&ignoreCase, "ignore-case", true, "特征匹配忽略大小写 (默认: true)")

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

// validateParams 参数校验
func validateParams() error {
	if input == "" {
		return errors.New("必须指定 -input 参数")
	}
	if _, err := os.Stat(input); os.IsNotExist(err) {
		return fmt.Errorf("输入文件不存在: %s", input)
	}

	// 传输层协议校验
	supportedProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "": true}
	if !supportedProtos[strings.ToLower(proto)] {
		return errors.New("proto仅支持 tcp/udp/icmp")
	}

	// 应用层协议校验
	supportedApps := map[string]bool{
		"http": true, "https": true, "ssh": true, "mysql": true, "redis": true,
		"tcp-text": true, "tcp-binary": true, "tcp-no-payload": true, "": true,
	}
	if !supportedApps[strings.ToLower(app)] {
		return errors.New("app支持: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload")
	}

	// 端口范围校验
	if sport != 0 && (sport < 1 || sport > 65535) {
		return errors.New("sport必须在 1-65535 之间")
	}
	if dport != 0 && (dport < 1 || dport > 65535) {
		return errors.New("dport必须在 1-65535 之间")
	}

	// IP格式校验
	if sip != "" && net.ParseIP(sip) == nil {
		return fmt.Errorf("非法源IP: %s", sip)
	}
	if dip != "" && net.ParseIP(dip) == nil {
		return fmt.Errorf("非法目的IP: %s", dip)
	}

	// 正则格式校验
	if regexStr != "" {
		if _, err := regexp.Compile(regexStr); err != nil {
			return fmt.Errorf("非法正则表达式: %s (错误: %v)", regexStr, err)
		}
	}

	// 输出目录创建
	if outputDir != "" {
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("创建输出目录失败: %v", err)
			}
		}
	}

	return nil
}

// processPcap 解析PCAP文件
func processPcap() error {
	handle, err := pcap.OpenOffline(input)
	if err != nil {
		return fmt.Errorf("打开pcap失败: %v", err)
	}
	defer handle.Close()

	originalLinkType = handle.LinkType()

	// 解码层初始化
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

		// 仅处理TCP协议
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			continue
		}

		// 获取IP地址
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

		// 基础过滤
		if !applyBasicFilters(pktSIP, pktDIP, pktSPort, pktDPort, transProto) {
			continue
		}

		// 添加到会话
		addToSession(pktSIP, pktDIP, pktSPort, pktDPort, transProto, payload, len(payload) > 0, packet)
	}

	return nil
}

// applyBasicFilters 基础过滤(支持双向匹配)
func applyBasicFilters(pktSIP, pktDIP string, pktSPort, pktDPort uint, transProto string) bool {
	// 传输层协议过滤
	if proto != "" && !strings.EqualFold(transProto, proto) {
		return false
	}

	// IP双向匹配
	ipMatch := true
	if sip != "" || dip != "" {
		forwardIPMatch := (sip == "" || strings.EqualFold(pktSIP, sip)) && (dip == "" || strings.EqualFold(pktDIP, dip))
		reverseIPMatch := (sip == "" || strings.EqualFold(pktSIP, dip)) && (dip == "" || strings.EqualFold(pktDIP, sip))
		ipMatch = forwardIPMatch || reverseIPMatch
	}

	// 端口双向匹配
	portMatch := true
	if sport != 0 || dport != 0 {
		forwardPortMatch := (sport == 0 || pktSPort == sport) && (dport == 0 || pktDPort == dport)
		reversePortMatch := (sport == 0 || pktSPort == dport) && (dport == 0 || pktDPort == sport)
		portMatch = forwardPortMatch || reversePortMatch
	}

	return ipMatch && portMatch
}

// getNormalizedSessionKey 生成归一化会话Key(解决双向流量拆分)
func getNormalizedSessionKey(sip, dip string, sport, dport uint, proto string) SessionKey {
	srcAddr := fmt.Sprintf("%s:%d", sip, sport)
	dstAddr := fmt.Sprintf("%s:%d", dip, dport)

	// 字典序排序确保双向流量同Key
	if srcAddr > dstAddr {
		srcAddr, dstAddr = dstAddr, srcAddr
	}

	return SessionKey{
		SrcAddr: srcAddr,
		DstAddr: dstAddr,
		Proto:   proto,
	}
}

// addToSession 添加数据包到会话
func addToSession(pktSIP, pktDIP string, pktSPort, pktDPort uint, transProto string, payload []byte, hasValidPayload bool, packet gopacket.Packet) {
	key := getNormalizedSessionKey(pktSIP, pktDIP, pktSPort, pktDPort, transProto)

	if _, exists := sessions[key]; !exists {
		sessions[key] = &Session{
			Key:             key,
			AppProto:        "tcp-no-payload",
			RegexMatch:      "",
			Packets:         make([]gopacket.Packet, 0),
			TCPFlowCache:    make([]byte, 0),
			hasValidPayload: false,
		}
	}

	session := sessions[key]
	if len(payload) > 0 {
		session.TCPFlowCache = append(session.TCPFlowCache, payload...)
		session.hasValidPayload = true
	}
	session.Packets = append(session.Packets, packet)
}

// identifyAppProtocols 应用层协议识别+协议过滤
func identifyAppProtocols() {
	validSessions := make(map[SessionKey]*Session)

	// 有序遍历确保识别一致
	var sortedKeys []SessionKey
	for key := range sessions {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i].SrcAddr+sortedKeys[i].DstAddr < sortedKeys[j].SrcAddr+sortedKeys[j].DstAddr
	})

	// 协议识别优先级: SSH→HTTPS→MySQL→Redis→文本/二进制
	protocolRules := []struct {
		name  string
		match func(payload string) bool
	}{
		{
			name: "ssh",
			match: func(payload string) bool {
				return len(payload) >= 4 && strings.HasPrefix(strings.ToLower(payload), "ssh-")
			},
		},
		{
			name: "https",
			match: func(payload string) bool {
				return len(payload) >= 3 && payload[0] == 0x16 && payload[1] == 0x03 && (payload[2] >= 0x01 && payload[2] <= 0x04)
			},
		},
		{
			name: "mysql",
			match: func(payload string) bool {
				return len(payload) >= 6 && (strings.HasPrefix(payload, "\x0aMySQL") || strings.HasPrefix(payload, "\x0amariadb"))
			},
		},
		{
			name: "redis",
			match: func(payload string) bool {
				return redisRegex.MatchString(payload)
			},
		},
	}

	for _, key := range sortedKeys {
		session := sessions[key]
		appProto := "tcp-binary"

		if !session.hasValidPayload || len(session.TCPFlowCache) == 0 {
			appProto = "tcp-no-payload"
		} else {
			fullPayload := session.TCPFlowCache
			payloadStr := string(fullPayload)

			// 优先识别HTTP
			if httpRegex.MatchString(payloadStr) {
				appProto = "http"
			} else {
				// 按优先级识别其他协议
				for _, rule := range protocolRules {
					if rule.match(payloadStr) {
						appProto = rule.name
						break
					}
				}

				// 未识别协议判断文本/二进制
				if appProto == "tcp-binary" && isTextPayload(fullPayload) {
					appProto = "tcp-text"
				}
			}
		}

		session.AppProto = appProto

		// 正则匹配
		if regexStr != "" {
			match := regexp.MustCompile(regexStr).Find(session.TCPFlowCache)
			if match != nil {
				session.RegexMatch = sanitizeFilename(string(match[:min(len(match), 32)]))
			} else {
				session.RegexMatch = ""
			}
		}

		// 应用层协议过滤
		if app == "" || strings.EqualFold(session.AppProto, app) {
			validSessions[key] = session
		}
	}

	sessions = validSessions
}

// isTextPayload 判断是否为文本负载
func isTextPayload(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	// 检查非打印字符
	for _, b := range payload {
		if !(b >= 32 && b <= 126 || b == 9 || b == 10 || b == 11 || b == 13) {
			return false
		}
	}
	// 检查非空白字符
	nonSpaceCount := 0
	for _, b := range payload {
		if b != 32 && b != 9 && b != 10 && b != 11 && b != 13 {
			nonSpaceCount++
			break
		}
	}
	return nonSpaceCount > 0
}

// sanitizeFilename 清理文件名非法字符
func sanitizeFilename(name string) string {
	reg := regexp.MustCompile(`[\\/:*?"<>|]`)
	return reg.ReplaceAllString(name, "_")
}

// outputResults 结果输出
func outputResults() error {
	if len(sessions) == 0 {
		fmt.Println("\n无符合条件的会话可输出")
		return nil
	}

	// 有序输出确保结果一致
	var sortedKeys []SessionKey
	for key := range sessions {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i].SrcAddr+sortedKeys[i].DstAddr < sortedKeys[j].SrcAddr+sortedKeys[j].DstAddr
	})

	// 仅打印结果
	if outputDir == "" {
		fmt.Println("\n会话详情: ")
		fmt.Println("--------------------------------------------------------------------------------------------------")
		fmt.Printf("%-5s %-7s %-30s %-30s %s\n", "传输层", "应用层协议", "源地址:端口", "目的地址:端口", "正则命中")
		fmt.Println("--------------------------------------------------------------------------------------------------")
		for _, key := range sortedKeys {
			session := sessions[key]
			regex := session.RegexMatch
			if regex == "" {
				regex = "-"
			}
			fmt.Printf("%-8s %-12s %-35s %-35s %s\n",
				session.Key.Proto,
				session.AppProto,
				session.Key.SrcAddr,
				session.Key.DstAddr,
				regex,
			)
		}
		return nil
	}

	// 输出到文件
	for _, key := range sortedKeys {
		session := sessions[key]
		filename := fmt.Sprintf("%s_%s_%s",
			strings.ReplaceAll(session.Key.SrcAddr, ":", "_"),
			strings.ReplaceAll(session.Key.DstAddr, ":", "_"),
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
		if err := writer.WriteFileHeader(65536, originalLinkType); err != nil {
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

		fmt.Printf("已保存会话: %s (%d pkts)\n", filePath, len(session.Packets))
	}

	return nil
}

// printUsage 打印使用说明
func printUsage() {
	fmt.Println(`
使用语法: 
  pcap-filter [参数]

参数说明: 
  -input          string   输入pcap文件路径 (必填)
  -proto          string   传输层协议过滤 (可选: tcp/udp/icmp)
  -app            string   应用层协议过滤 (可选: http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload)
  -sip            string   源IP过滤 (可选, 双向匹配)
  -sport          uint     源端口过滤 (可选, 1-65535, 双向匹配)
  -dip            string   目的IP过滤 (可选, 双向匹配)
  -dport          uint     目的端口过滤 (可选, 1-65535, 双向匹配)
  -regex          string   正则过滤表达式 (可选)
  -regex-invert   bool     正则取反 (默认: false)
  -output         string   输出目录 (可选)
  -custom-feature string   自定义协议特征 (可选)
  -ignore-case    bool     特征匹配忽略大小写 (默认: true)

使用样例: 
  1. 正则正向匹配: 保留含 BAS_ID=.{16} 的HTTP会话(打印结果)
     pcap-filter -input traffic.pcap -app http -regex "BAS_ID=.{16}"

  2. 正则取反匹配: 保留不含 BAS_ID=.{16} 的HTTP会话(保存文件)
     pcap-filter -input traffic.pcap -app http -regex "BAS_ID=.{16}" -regex-invert -output ./non_bas_sessions

  3. IP+端口过滤: 保留源IP为192.168.1.1、端口8080的TCP会话
     pcap-filter -input traffic.pcap -proto tcp -sip 192.168.1.1 -sport 8080 -output ./tcp_sessions

  4. 双向IP匹配: 保留涉及10.0.0.1(源/目的均可)的Redis会话
     pcap-filter -input traffic.pcap -app redis -sip 10.0.0.1 -output ./redis_related

  5. 传输层协议过滤: 仅保留UDP会话并按协议分类
     pcap-filter -input traffic.pcap -proto udp -output ./udp_sessions

  6. 多条件组合过滤: 保留192.168.1.0/24网段、含"login"的文本会话
     pcap-filter -input traffic.pcap -app tcp-text -sip 192.168.1.0/24 -regex "login" -output ./login_sessions

  7. 仅打印结果: 不输出文件, 仅在终端显示符合条件的SSH会话
     pcap-filter -input traffic.pcap -app ssh -regex "SSH-2.0"

  8. 忽略大小写匹配: 保留含"USER"或"user"的HTTP会话
     pcap-filter -input traffic.pcap -app http -regex "user" -ignore-case true

  9. 空白正则过滤: 保留所有MySQL会话(仅按应用层协议过滤)
     pcap-filter -input traffic.pcap -app mysql -output ./all_mysql_sessions

  10. 复杂正则匹配: 保留含手机号(11位数字)的TCP文本会话
     pcap-filter -input traffic.pcap -app tcp-text -regex "1[3-9]\d{9}" -output ./phone_related
`)
}

// min 取最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}