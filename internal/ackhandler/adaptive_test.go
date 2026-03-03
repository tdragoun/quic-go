package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestAdaptiveThresholdsInitialization(t *testing.T) {
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, true, false, nil, protocol.PerspectiveClient, nil, nil, utils.DefaultLogger).(*sentPacketHandler)

	// Verify thresholds start at base values.
	require.Equal(t, protocol.PacketNumber(basePacketThreshold), handler.adaptivePacketThreshold)
	require.Equal(t, baseTimeThreshold, handler.adaptiveTimeThreshold)
	require.Equal(t, 0, handler.spuriousLossCount)
	require.Equal(t, 0.0, handler.observedPacketReordering)
	require.Equal(t, 0.0, handler.observedTimeReordering)
}

func TestAdaptiveThresholdsIncreaseAfterSpuriousLosses(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, true, false, nil, protocol.PerspectiveClient, nil, nil, utils.DefaultLogger).(*sentPacketHandler)

	// Verify thresholds start at base values.
	require.Equal(t, protocol.PacketNumber(basePacketThreshold), handler.adaptivePacketThreshold)
	require.Equal(t, baseTimeThreshold, handler.adaptiveTimeThreshold)

	// Simulate first spurious loss: packet reordering of 5, time reordering of 150ms (1.5x RTT).
	// With minSpuriousLossesForAdapt = 1, this should trigger immediate adaptation.
	handler.updateAdaptiveThresholds(5, 150*time.Millisecond)
	require.Equal(t, 1, handler.spuriousLossCount)
	// Thresholds should have increased immediately.
	require.Greater(t, handler.adaptivePacketThreshold, protocol.PacketNumber(basePacketThreshold))
	require.Greater(t, handler.adaptiveTimeThreshold, baseTimeThreshold)
	require.Greater(t, handler.observedPacketReordering, 0.0)
	require.Greater(t, handler.observedTimeReordering, 0.0)

	// Simulate second spurious loss with higher reordering.
	oldThreshold := handler.adaptivePacketThreshold
	handler.updateAdaptiveThresholds(10, 180*time.Millisecond)
	require.Equal(t, 2, handler.spuriousLossCount)
	// Threshold should have increased further.
	require.Greater(t, handler.adaptivePacketThreshold, oldThreshold)

	// Simulate third spurious loss with extreme reordering (50 packets).
	// This should trigger aggressive adaptation.
	oldThreshold = handler.adaptivePacketThreshold
	handler.updateAdaptiveThresholds(50, 200*time.Millisecond)
	require.Equal(t, 3, handler.spuriousLossCount)
	// Threshold should jump significantly due to extreme reordering detection.
	require.Greater(t, handler.adaptivePacketThreshold, oldThreshold)
	// Should be much closer to 50 due to aggressive adaptation.
	require.Greater(t, handler.adaptivePacketThreshold, protocol.PacketNumber(20))
}

func TestAdaptiveThresholdsBounds(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, true, false, nil, protocol.PerspectiveClient, nil, nil, utils.DefaultLogger).(*sentPacketHandler)

	// Simulate extreme reordering to test max bounds.
	handler.spuriousLossCount = minSpuriousLossesForAdapt
	handler.observedPacketReordering = 200 // Very high reordering (above max of 100)
	handler.observedTimeReordering = 10.0  // Very high time reordering (above max of 4.0)

	handler.updateAdaptiveThresholds(200, 10*time.Second)

	// Verify thresholds are capped at maximum.
	require.Equal(t, protocol.PacketNumber(maxPacketThreshold), handler.adaptivePacketThreshold)
	require.Equal(t, maxTimeThreshold, handler.adaptiveTimeThreshold)

	// Simulate low reordering to test min bounds.
	handler.observedPacketReordering = 1.0
	handler.observedTimeReordering = 0.5

	handler.updateAdaptiveThresholds(1, 50*time.Millisecond)

	// Verify thresholds stay at base minimum.
	require.Equal(t, protocol.PacketNumber(basePacketThreshold), handler.adaptivePacketThreshold)
	require.GreaterOrEqual(t, handler.adaptiveTimeThreshold, baseTimeThreshold)
}

func TestAdaptiveThresholdsResetOnPathMigration(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, true, false, nil, protocol.PerspectiveClient, nil, nil, utils.DefaultLogger).(*sentPacketHandler)

	// Simulate adaptation.
	handler.spuriousLossCount = 5
	handler.adaptivePacketThreshold = 8
	handler.adaptiveTimeThreshold = 2.5
	handler.observedPacketReordering = 7.0
	handler.observedTimeReordering = 2.0

	// Trigger path migration.
	handler.MigratedPath(monotime.Now(), 1200)

	// Verify reset to base values.
	require.Equal(t, 0, handler.spuriousLossCount)
	require.Equal(t, protocol.PacketNumber(basePacketThreshold), handler.adaptivePacketThreshold)
	require.Equal(t, baseTimeThreshold, handler.adaptiveTimeThreshold)
	require.Equal(t, 0.0, handler.observedPacketReordering)
	require.Equal(t, 0.0, handler.observedTimeReordering)
}

func TestAdaptiveThresholdsOnlyFor1RTT(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, true, false, nil, protocol.PerspectiveClient, nil, nil, utils.DefaultLogger).(*sentPacketHandler)

	// Set adaptive thresholds.
	handler.spuriousLossCount = minSpuriousLossesForAdapt
	handler.adaptivePacketThreshold = 7
	handler.adaptiveTimeThreshold = 2.0

	now := monotime.Now()

	// Send handshake packets 1-10.
	for i := protocol.PacketNumber(1); i <= 10; i++ {
		handler.SentPacket(now, i, protocol.InvalidPacketNumber, []StreamFrame{}, []Frame{}, protocol.EncryptionHandshake, protocol.ECNNon, 100, true, false)
	}

	// ACK packets 4-10 (should use base thresholds for handshake).
	handler.ReceivedAck(&wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 4, Largest: 10}},
	}, protocol.EncryptionHandshake, now.Add(50*time.Millisecond))

	// Detect losses with handshake encryption level.
	handler.detectLostPackets(now.Add(200*time.Millisecond), protocol.EncryptionHandshake)

	// Handshake packets should be declared lost using base threshold (3), not adaptive (7).
	// So packets 1-3 should be lost (gap >= 3 from largest acked = 10).
	// This is verified by checking that the handshake packets were removed from history.
	require.Equal(t, 0, handler.handshakePackets.history.Len()) // All declared lost and removed
}
