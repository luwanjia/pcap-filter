pcap-filter(PCAP会话信息过滤工具)
===

# 1 功能描述
## 1.1 需求来源
* 一个pcap解析并过滤会话信息的工具
* 默认打印pcap中所有四元组信息
* 支持过滤条件
  * 按照传输层协议过滤
  * 按照应用层协议过滤(可能与传输层协议存在关联，帮忙考虑如何处理)
  * 按照四元组过滤(支持sip/sport/dip/dport单个条件过滤和组合过滤)
  * 按照正则检索过滤
* 过滤完成之后，支持按每个会话独立输出到pcap文件
  * 如果未指定输出目录，则只打印四元组，不保存pcap文件
    如果使用了正则过滤，打印四元组信息+正则命中内容，正则内容最大32字节
  * 一个会话保存到一个文件
  * 文件命名规则："<sip>_<sport>_<dip>_<dport>_<regular>.pcap"
    regular是正则表达式命中的部分，最大32字节
* 当参数检查失败时，打印命令使用介绍和样例

## 1.2 用法
```
使用语法：
  pcap-filter [参数]

参数说明：
  -input          string   输入pcap文件路径（必填）
  -proto          string   传输层协议过滤（可选：tcp/udp/icmp）
  -app            string   应用层协议过滤（可选：http/https/ssh/mysql/redis/tcp-text/tcp-binary/tcp-no-payload）
  -sip            string   源IP过滤（可选，支持IPv4/IPv6）
  -sport          uint     源端口过滤（可选，范围：1-65535）
  -dip            string   目的IP过滤（可选，支持IPv4/IPv6）
  -dport          uint     目的端口过滤（可选，范围：1-65535）
  -regex          string   正则过滤表达式（可选，匹配应用层数据）
  -output         string   输出目录路径（可选，不指定则仅打印结果）
  -custom-feature string  自定义协议特征（可选，匹配应用层数据）
  -ignore-case    bool     特征匹配忽略大小写（可选，默认：true）

使用样例：
  1. 分析pcap文件并打印所有会话：
     pcap-filter -input traffic.pcap

  2. 过滤HTTP协议会话并保存到指定目录：
     pcap-filter -input traffic.pcap -app http -output ./http_sessions

  3. 过滤源IP为192.168.1.100、目的端口为80的TCP会话：
     pcap-filter -input traffic.pcap -proto tcp -sip 192.168.1.100 -dport 80

  4. 用正则匹配含特定参数的HTTP会话：
     pcap-filter -input traffic.pcap -app http -regex "REQ_ID=.{16}" -output ./target_sessions
```

# 2 编译
## 2.1 依赖
```
"github.com/google/gopacket"
"github.com/google/gopacket/layers"
"github.com/google/gopacket/pcap"
"github.com/google/gopacket/pcapgo"
```
## 2.2 编译
```
go mod init pcap-tool
go mod tidy
go build -o pcap-filter main.go
```
