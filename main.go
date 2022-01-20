package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var (
	device = "enp4s0"
	snapshotLen int32 = 1024
	err error
	timeout = 30 * time.Second
	handle *pcap.Handle
	buffer gopacket.SerializeBuffer
	options gopacket.SerializeOptions
)

func main() {

	handle, err = pcap.OpenLive(device, snapshotLen, false, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	rawBytes := []byte{0x26, 0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC: net.HardwareAddr{0x01, 0x80, 0xC2, 0x00, 0x00, 0x00},
	}

	buffer = gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
    buffer, options,
		ethernetLayer,
		gopacket.Payload(rawBytes),
	)
	if err != nil {
		return
	}
	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}
