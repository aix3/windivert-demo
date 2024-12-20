package main

import (
	"bytes"
	"fmt"
	"log"
	windrivet "windivert"

	"windivert/utils"
	"windivert/utils/prependable"

	"github.com/imgk/divert-go"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// HTTP 响应
const httpResponse = "HTTP/1.1 200 OK\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"Request blocked!"

func main() {
	filter := "outbound && !loopback && ip && tcp.PayloadLength > 0"

	handle, err := divert.Open(filter, divert.LayerNetwork, 0, 0)
	if err != nil {
		log.Fatalf("Error opening WinDivert: %v", err)
	}
	defer handle.Close()
	log.Println("open windivert...")

	ifIdx, subIfIdx, err := utils.GetInterfaceIndex()
	if err != nil {
		panic(err)
	}

	addr := windrivet.Address{
		Address: new(divert.Address),
	}
	nw := addr.Network()
	nw.InterfaceIndex = ifIdx
	nw.SubInterfaceIndex = subIfIdx

	packet := make([]byte, 65535)
	for {
		// 接收数据包
		packetLen, err := handle.Recv(packet, addr.Address)
		if err != nil {
			log.Printf("Error receiving packet: %v", err)
			continue
		}

		ip := header.IPv4(packet[:packetLen])
		tcp := header.TCP(ip.Payload())
		// 检查是否为 HTTP 请求
		if bytes.HasPrefix(tcp.Payload(), []byte("GET ")) {
			fmt.Println("HTTP request detected")

			// 发送 RST 到 HTTP 服务端，断开此连接
			rst := createRstPacket(ip, tcp)
			_, err := handle.Send(rst, addr.Address)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
			}

			addr.SetDirection(windrivet.Inbound)

			// 发送自定义的 response 到 HTTP 客户端
			resp := createDataPacket(ip, tcp, []byte(httpResponse))
			_, err = handle.Send(resp, addr.Address)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
			}

			// 发送 FIN 到 HTTP 客户端
			fin := createFinPacket(ip, tcp, uint32(len(httpResponse)))
			_, err = handle.Send(fin, addr.Address)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
			}
		}
	}
}

func createRstPacket(ip header.IPv4, otcp header.TCP) []byte {
	tcpSize := header.TCPMinimumSize
	hdr := prependable.New(header.IPv4MinimumSize + tcpSize)
	tcp := header.TCP(hdr.Prepend(tcpSize))

	tcp.Encode(&header.TCPFields{
		SrcPort:    otcp.SourcePort(),
		DstPort:    otcp.DestinationPort(),
		SeqNum:     otcp.SequenceNumber(),
		AckNum:     otcp.AckNumber(),
		Flags:      header.TCPFlagAck | header.TCPFlagRst,
		WindowSize: otcp.WindowSize(),
		DataOffset: 20,
	})

	tcp.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(
		ip.TransportProtocol(),
		ip.SourceAddress(),
		ip.DestinationAddress(),
		uint16(len(tcp)),
	)
	tcp.SetChecksum(^tcp.CalculateChecksum(sum))

	encodeIPv4Header(
		hdr.Prepend(header.IPv4MinimumSize),
		tcpSize+header.IPv4MinimumSize,
		header.TCPProtocolNumber,
		ip.SourceAddress(),
		ip.DestinationAddress(),
	)
	return hdr.View()
}

func createDataPacket(ip header.IPv4, otcp header.TCP, payload []byte) []byte {
	tcpSize := header.TCPMinimumSize + len(payload)
	hdr := prependable.New(header.IPv4MinimumSize + tcpSize)
	tcp := header.TCP(hdr.Prepend(tcpSize))

	tcp.Encode(&header.TCPFields{
		SrcPort:    otcp.DestinationPort(),
		DstPort:    otcp.SourcePort(),
		SeqNum:     otcp.AckNumber(),
		AckNum:     otcp.SequenceNumber() + uint32(len(payload)),
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: otcp.WindowSize(),
		DataOffset: 20,
	})

	copy(tcp[header.TCPMinimumSize:], payload)

	tcp.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(
		ip.TransportProtocol(),
		ip.DestinationAddress(),
		ip.SourceAddress(),
		uint16(len(tcp)),
	)
	sum = checksum.Checksum(payload, sum)
	tcp.SetChecksum(^tcp.CalculateChecksum(sum))

	encodeIPv4Header(
		hdr.Prepend(header.IPv4MinimumSize),
		tcpSize+header.IPv4MinimumSize,
		header.TCPProtocolNumber,
		ip.DestinationAddress(),
		ip.SourceAddress(),
	)
	return hdr.View()
}

func createFinPacket(ip header.IPv4, otcp header.TCP, payloadLen uint32) []byte {
	tcpSize := header.TCPMinimumSize
	hdr := prependable.New(header.IPv4MinimumSize + tcpSize)
	tcp := header.TCP(hdr.Prepend(tcpSize))

	tcp.Encode(&header.TCPFields{
		SrcPort:    otcp.DestinationPort(),
		DstPort:    otcp.SourcePort(),
		SeqNum:     otcp.AckNumber() + uint32(payloadLen),
		AckNum:     otcp.SequenceNumber() + uint32(len(otcp.Payload())),
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: otcp.WindowSize(),
		DataOffset: 20,
	})

	tcp.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		ip.DestinationAddress(),
		ip.SourceAddress(),
		uint16(len(tcp)),
	)
	// sum = checksum.Checksum(payload, sum)
	tcp.SetChecksum(^tcp.CalculateChecksum(sum))

	encodeIPv4Header(
		hdr.Prepend(header.IPv4MinimumSize),
		tcpSize+header.IPv4MinimumSize,
		header.TCPProtocolNumber,
		ip.DestinationAddress(),
		ip.SourceAddress(),
	)
	return hdr.View()
}

func encodeIPv4Header(v []byte, totalLen int, transProto tcpip.TransportProtocolNumber, srcAddr, dstAddr tcpip.Address) {
	ip := header.IPv4(v)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		Protocol:    uint8(transProto),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
}
