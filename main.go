package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device            = "enp4s0"
	snapshotLen int32 = 1024
	err         error
	timeout     = 30 * time.Second
	handle      *pcap.Handle
	buffer      gopacket.SerializeBuffer
	options     gopacket.SerializeOptions

	destAddressFirst  byte = 0x01
	destAddressSecond byte = 0x80
	destAddressThird  byte = 0xc2
	destAddressFourth byte = 0x00
	destAddressFifth  byte = 0x00
	destAddressSixth  byte = 0x00

	sourceAddressFirst  byte = 0x01
	sourceAddressSecond byte = 0x01
	sourceAddressThird  byte = 0x01
	sourceAddressFourth byte = 0x01
	sourceAddressFifth  byte = 0x01
	sourceAddressSixth  byte = 0x01

	lengthFirst  byte = 0x00
	lengthSecond byte = 0x26

	DSAP byte = 0x42

	SSAP byte = 0x42

	control byte = 0x03

	protocolIDFirst  byte = 0x00
	protocolIDSecond byte = 0x00

	protocolVersionID byte = 0x00

	BPDUType byte = 0x00

	BPDUFlags byte = 0x00

	rootBridgePriority byte = 0x80

	rootBridgeSystemIDExtension byte = 0x01

	rootBridgeSystemIDFirst  byte = 0x01
	rootBridgeSystemIDSecond byte = 0x01
	rootBridgeSystemIDThird  byte = 0x01
	rootBridgeSystemIDFourth byte = 0x01
	rootBridgeSystemIDFifth  byte = 0x01
	rootBridgeSystemIDSixth  byte = 0x01

	rootPathCostFirst  byte = 0x00
	rootPathCostSecond byte = 0x00
	rootPathCostThird  byte = 0x00
	rootPathCostFourth byte = 0x00

	bridgePriority          byte = 0x80
	bridgeSystemIDExtension byte = 0x01

	bridgeSystemIDFirst  byte = 0x01
	bridgeSystemIDSecond byte = 0x01
	bridgeSystemIDThird  byte = 0x01
	bridgeSystemIDFourth byte = 0x01
	bridgeSystemIDFifth  byte = 0x01
	bridgeSystemIDSixth  byte = 0x01

	portIDFirst  byte = 0x80
	portIDSecond byte = 0x01

	messageAgeFirst  byte = 0x00
	messageAgeSecond byte = 0x00

	maxAgeFirst  byte = 0x14
	maxAgeSecond byte = 0x00

	helloTimeFirst  byte = 0x02
	helloTimeSecond byte = 0x00

	forwardDelayFirst  byte = 0x0f
	forwardDelaySecond byte = 0x00

	padding byte = 0x00
)

func main() {

	handle, err = pcap.OpenLive(device, snapshotLen, false, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	rawBytes := []byte{destAddressFirst, destAddressSecond, destAddressThird, destAddressFourth, destAddressFifth, destAddressSixth, sourceAddressFirst, sourceAddressSecond, sourceAddressThird, sourceAddressFourth, sourceAddressFifth, sourceAddressSixth, lengthFirst, lengthSecond, DSAP, SSAP, control, protocolIDFirst, protocolIDSecond, protocolVersionID, BPDUType, BPDUFlags, rootBridgePriority, rootBridgeSystemIDExtension, rootBridgeSystemIDFirst, rootBridgeSystemIDSecond, rootBridgeSystemIDThird, rootBridgeSystemIDFourth, rootBridgeSystemIDFifth, rootBridgeSystemIDSixth, rootPathCostFirst, rootPathCostSecond, rootPathCostThird, rootPathCostThird, rootPathCostFourth, bridgePriority, bridgeSystemIDExtension, bridgeSystemIDFirst, bridgeSystemIDSecond, bridgeSystemIDThird, bridgeSystemIDFourth, bridgeSystemIDFifth, bridgeSystemIDSixth, portIDFirst, portIDSecond, messageAgeFirst, messageAgeSecond, maxAgeFirst, maxAgeSecond, helloTimeFirst, helloTimeSecond, forwardDelayFirst, forwardDelaySecond, padding, padding, padding, padding, padding, padding}
	buffer = gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(
		buffer, options,
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
