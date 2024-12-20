package main

import (
	"bytes"
	"fmt"
	"log"
	"windivert/utils"

	"github.com/imgk/divert-go"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func main() {
	filter := "!loopback && ip && tcp.PayloadLength > 0"

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

		detectHTTPPacket(packet[:packetLen], addr)

		_, err = handle.Send(packet[:packetLen], addr)
		if err != nil {
			log.Printf("Error sending packet: %v", err)
		}
	}
}

func detectHTTPPacket(packet []byte, addr *divert.Address) {
	ip := header.IPv4(packet)
	tcp := header.TCP(ip.Payload())

	// 检查是否为 HTTP 请求
	payload := tcp.Payload()
	if bytes.HasPrefix(payload, []byte("GET ")) || bytes.HasPrefix(payload, []byte("POST ")) {
		fmt.Printf("HTTP request detected, addr: %+v\n", addr)
	}
	if bytes.HasPrefix(payload, []byte("HTTP/1.1 ")) {
		fmt.Printf("HTTP response detected, addr: %+v\n", addr)
	}
}
