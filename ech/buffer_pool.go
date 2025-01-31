package quic

import (
	"github.com/sagernet/quic-go"
)

type packetBuffer = quic.PacketBuffer

func getPacketBuffer() *packetBuffer {
	return quic.GetPacketBuffer()
}

func getLargePacketBuffer() *packetBuffer {
	return quic.GetLargePacketBuffer()
}
