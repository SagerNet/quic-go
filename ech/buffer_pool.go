package quic

import (
	"github.com/quic-go/quic-go"
)

type packetBuffer = quic.PacketBuffer

func getPacketBuffer() *packetBuffer {
	return quic.GetPacketBuffer()
}

func getLargePacketBuffer() *packetBuffer {
	return quic.GetLargePacketBuffer()
}
