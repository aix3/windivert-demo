package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"

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
	"Hello World!"

func main() {
	filter := "inbound && !loopback && ip && tcp.PayloadLength > 0"

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

	addr := new(divert.Address)
	nw := addr.Network()
	nw.InterfaceIndex = ifIdx
	nw.SubInterfaceIndex = subIfIdx

	packet := make([]byte, 65535)
	for {
		// 接收数据包
		packetLen, err := handle.Recv(packet, addr)
		if err != nil {
			log.Printf("Error receiving packet: %v", err)
			continue
		}

		ip := header.IPv4(packet[:packetLen])
		tcp := header.TCP(ip.Payload())
		// 检查是否为 HTTP 请求
		if bytes.HasPrefix(tcp.Payload(), []byte("HTTP/1.1")) {
			res, _ := http.ReadResponse(bufio.NewReader(bytes.NewReader(tcp.Payload())), nil)
			fmt.Println("HTTP response detected: ", res.Header)

			resp := createDataPacket(ip, tcp, []byte(httpResponse))
			_, err := handle.Send(resp, addr)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
			}

			fin := createFinPacket(ip, tcp, uint32(len(httpResponse)))
			_, err = handle.Send(fin, addr)
			if err != nil {
				log.Printf("Error sending packet: %v", err)
			}
		}
	}
}

func createDataPacket(ip header.IPv4, otcp header.TCP, payload []byte) []byte {
	tcpSize := header.TCPMinimumSize + len(payload)
	hdr := prependable.New(header.IPv4MinimumSize + tcpSize)
	tcp := header.TCP(hdr.Prepend(tcpSize))

	tcp.Encode(&header.TCPFields{
		SrcPort:    otcp.SourcePort(),
		DstPort:    otcp.DestinationPort(),
		SeqNum:     otcp.SequenceNumber(),
		AckNum:     otcp.AckNumber(),
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: otcp.WindowSize(),
		DataOffset: 20,
	})

	copy(tcp[header.TCPMinimumSize:], payload)

	tcp.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(
		ip.TransportProtocol(),
		ip.SourceAddress(),
		ip.DestinationAddress(),
		uint16(len(tcp)),
	)
	sum = checksum.Checksum(payload, sum)
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

func createFinPacket(ip header.IPv4, otcp header.TCP, payloadLen uint32) []byte {
	tcpSize := header.TCPMinimumSize
	hdr := prependable.New(header.IPv4MinimumSize + tcpSize)
	tcp := header.TCP(hdr.Prepend(tcpSize))

	tcp.Encode(&header.TCPFields{
		SrcPort:    otcp.SourcePort(),
		DstPort:    otcp.DestinationPort(),
		SeqNum:     otcp.SequenceNumber() + payloadLen,
		AckNum:     otcp.AckNumber(),
		Flags:      header.TCPFlagAck | header.TCPFlagFin,
		WindowSize: otcp.WindowSize(),
		DataOffset: 20,
	})

	tcp.SetChecksum(0)
	sum := header.PseudoHeaderChecksum(
		header.TCPProtocolNumber,
		ip.SourceAddress(),
		ip.DestinationAddress(),
		uint16(len(tcp)),
	)
	// sum = checksum.Checksum(payload, sum)
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
