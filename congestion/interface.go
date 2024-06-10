package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

type (
	ByteCount    protocol.ByteCount
	PacketNumber protocol.PacketNumber
)

type CongestionControl interface {
	SetRTTStatsProvider(provider RTTStatsProvider)
	TimeUntilSend(bytesInFlight ByteCount) time.Time
	HasPacingBudget(now time.Time) bool
	OnPacketSent(sentTime time.Time, bytesInFlight ByteCount, packetNumber PacketNumber, bytes ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number PacketNumber, ackedBytes ByteCount, priorInFlight ByteCount, eventTime time.Time)
	OnCongestionEvent(number PacketNumber, lostBytes ByteCount, priorInFlight ByteCount)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(size ByteCount)
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() ByteCount
}

type RTTStatsProvider interface {
	MinRTT() time.Duration
	LatestRTT() time.Duration
	SmoothedRTT() time.Duration
	MeanDeviation() time.Duration
	MaxAckDelay() time.Duration
	PTO(includeMaxAckDelay bool) time.Duration
	UpdateRTT(sendDelta, ackDelay time.Duration)
	SetMaxAckDelay(mad time.Duration)
	SetInitialRTT(t time.Duration)
}
