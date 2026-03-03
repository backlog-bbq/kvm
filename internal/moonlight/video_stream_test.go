package moonlight

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/klauspost/reedsolomon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNVVideoPacketSerialization(t *testing.T) {
	vp := &videoPacketizer{}
	pkt := vp.buildVideoPacket(
		1000,   // rtpTimestamp
		42,     // frameIndex
		3,      // streamPacketIndex
		nvVideoFlagSOF|nvVideoFlagContainsPicData, // flags
		0,    // extraFlags
		0x10, // multiFecFlags
		0x00, // multiFecBlocks
		(5<<22)|(10<<12)|20, // fecInfo
		[]byte{0xAA, 0xBB},
	)

	// Total size = 32 (header) + 2 (payload) = 34.
	assert.Equal(t, 34, len(pkt))

	// RTP header checks.
	assert.Equal(t, byte(0x80), pkt[0]) // V=2
	assert.Equal(t, byte(videoPayloadType), pkt[1]&0x7F)
	assert.Equal(t, uint16(0), binary.BigEndian.Uint16(pkt[2:4])) // first seq
	assert.Equal(t, uint32(1000), binary.BigEndian.Uint32(pkt[4:8]))
	assert.Equal(t, uint32(videoSSRC), binary.BigEndian.Uint32(pkt[8:12]))

	// Reserved zeros.
	assert.Equal(t, []byte{0, 0, 0, 0}, pkt[12:16])

	// NV_VIDEO_PACKET at offset 16.
	nv := pkt[16:32]
	assert.Equal(t, uint32(3<<8), binary.LittleEndian.Uint32(nv[0:4]))  // streamPacketIndex << 8
	assert.Equal(t, uint32(42), binary.LittleEndian.Uint32(nv[4:8]))     // frameIndex
	assert.Equal(t, byte(nvVideoFlagSOF|nvVideoFlagContainsPicData), nv[8])
	assert.Equal(t, byte(0), nv[9])    // extraFlags
	assert.Equal(t, byte(0x10), nv[10]) // multiFecFlags
	assert.Equal(t, byte(0x00), nv[11]) // multiFecBlocks
	expectedFecInfo := uint32((5 << 22) | (10 << 12) | 20)
	assert.Equal(t, expectedFecInfo, binary.LittleEndian.Uint32(nv[12:16]))

	// Payload.
	assert.Equal(t, []byte{0xAA, 0xBB}, pkt[32:34])
}

func TestVideoFrameHeader(t *testing.T) {
	t.Run("IDR frame", func(t *testing.T) {
		h264 := []byte{0x00, 0x00, 0x00, 0x01, 0x65} // IDR NALU
		payload := buildFramePayload(h264, 2)

		assert.Equal(t, 8+len(h264), len(payload))
		assert.Equal(t, byte(0x01), payload[0]) // headerType
		assert.Equal(t, byte(2), payload[3])     // frameType = IDR
		// h264 data follows.
		assert.Equal(t, h264, payload[8:])
	})

	t.Run("P-frame", func(t *testing.T) {
		h264 := []byte{0x00, 0x00, 0x00, 0x01, 0x41}
		payload := buildFramePayload(h264, 1)
		assert.Equal(t, byte(1), payload[3]) // frameType = P
	})
}

func TestVideoPacketization(t *testing.T) {
	// A small H.264 frame that fits in a single packet.
	h264 := make([]byte, 100)
	h264[0], h264[1], h264[2], h264[3], h264[4] = 0, 0, 0, 1, 0x41 // P-frame NALU
	vf := videoFrame{data: h264, duration: time.Second / 60}

	// Use a mock connection to capture packets.
	vp := &videoPacketizer{}
	packets := collectVideoPackets(t, vp, vf)

	require.GreaterOrEqual(t, len(packets), 1, "should produce at least one data packet")

	// First packet should have SOF flag.
	nv := packets[0][16:32]
	flags := nv[8]
	assert.True(t, flags&nvVideoFlagSOF != 0, "first packet should have SOF")
	assert.True(t, flags&nvVideoFlagContainsPicData != 0, "data packet should have CONTAINS_PIC_DATA")
}

func TestVideoPacketizationMultiplePackets(t *testing.T) {
	// Create a frame larger than one shard to force multiple packets.
	h264 := make([]byte, videoPayloadSize*3) // 3+ data shards
	h264[0], h264[1], h264[2], h264[3], h264[4] = 0, 0, 0, 1, 0x41
	vf := videoFrame{data: h264, duration: time.Second / 60}

	vp := &videoPacketizer{}
	packets := collectVideoPackets(t, vp, vf)

	// Should have at least 3 data packets + parity packets.
	require.GreaterOrEqual(t, len(packets), 3)

	// Check SOF on first, EOF on last data packet.
	firstFlags := packets[0][24] // NV offset 8
	assert.True(t, firstFlags&nvVideoFlagSOF != 0, "first should have SOF")

	// Find last data packet (has CONTAINS_PIC_DATA flag).
	var lastDataIdx int
	for i, pkt := range packets {
		if pkt[24]&nvVideoFlagContainsPicData != 0 {
			lastDataIdx = i
		}
	}
	assert.True(t, packets[lastDataIdx][24]&nvVideoFlagEOF != 0, "last data packet should have EOF")
}

func TestVideoPacketizationIDRDetection(t *testing.T) {
	// IDR frame.
	idrFrame := []byte{0x00, 0x00, 0x00, 0x01, 0x65}
	assert.True(t, isIDRFrame(idrFrame))

	// SPS NALU (also indicates IDR).
	spsFrame := []byte{0x00, 0x00, 0x00, 0x01, 0x67}
	assert.True(t, isIDRFrame(spsFrame))

	// P-frame.
	pFrame := []byte{0x00, 0x00, 0x00, 0x01, 0x41}
	assert.False(t, isIDRFrame(pFrame))

	// Short 3-byte start code.
	idr3 := []byte{0x00, 0x00, 0x01, 0x65}
	assert.True(t, isIDRFrame(idr3))
}

func TestVideoFrameIndexIncrement(t *testing.T) {
	vp := &videoPacketizer{}
	h264 := []byte{0x00, 0x00, 0x01, 0x41, 0xFF}
	dur := time.Second / 60

	packets1 := collectVideoPackets(t, vp, videoFrame{data: h264, duration: dur})
	packets2 := collectVideoPackets(t, vp, videoFrame{data: h264, duration: dur})

	// frameIndex in NV_VIDEO_PACKET at offset 20 (16+4).
	fi1 := binary.LittleEndian.Uint32(packets1[0][20:24])
	fi2 := binary.LittleEndian.Uint32(packets2[0][20:24])
	assert.Equal(t, fi1+1, fi2, "frameIndex should increment per frame")
}

func TestVideoFECShardGeneration(t *testing.T) {
	tests := []struct {
		name          string
		numDataShards int
		wantParity    int
	}{
		{"1 shard", 1, 1},
		{"5 shards", 5, 1},
		{"10 shards", 10, 2},
		{"50 shards", 50, 10},
		{"100 shards", 100, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shards := make([][]byte, tt.numDataShards)
			for i := range shards {
				shards[i] = make([]byte, 100)
				shards[i][0] = byte(i)
			}

			numParity := (tt.numDataShards*fecPercentage + 99) / 100
			if numParity == 0 {
				numParity = 1
			}
			assert.Equal(t, tt.wantParity, numParity)

			parity, err := generateFECShards(shards, numParity)
			require.NoError(t, err)
			assert.Len(t, parity, numParity)

			// Each parity shard should be same size as data shards.
			for _, p := range parity {
				assert.Len(t, p, 100)
			}
		})
	}
}

func TestVideoFECBlockSplitting(t *testing.T) {
	// Under limit: single block.
	shards10 := make([][]byte, 10)
	for i := range shards10 {
		shards10[i] = []byte{byte(i)}
	}
	blocks := splitIntoFECBlocks(shards10)
	assert.Len(t, blocks, 1)
	assert.Len(t, blocks[0], 10)

	// Over limit: should split.
	shards300 := make([][]byte, 300)
	for i := range shards300 {
		shards300[i] = []byte{byte(i)}
	}
	blocks = splitIntoFECBlocks(shards300)
	assert.True(t, len(blocks) >= 2 && len(blocks) <= maxFECBlocks)
	total := 0
	for _, b := range blocks {
		total += len(b)
	}
	assert.Equal(t, 300, total)
}

func TestVideoFECInfoEncoding(t *testing.T) {
	shardIndex := uint32(5)
	dataShardCount := uint32(10)
	fecPct := uint32(20)

	fecInfo := (shardIndex << 22) | (dataShardCount << 12) | fecPct

	// Decode.
	gotShardIdx := fecInfo >> 22
	gotDataCount := (fecInfo >> 12) & 0x3FF
	gotPct := fecInfo & 0xFFF

	assert.Equal(t, shardIndex, gotShardIdx)
	assert.Equal(t, dataShardCount, gotDataCount)
	assert.Equal(t, fecPct, gotPct)
}

func TestVideoFECRecovery(t *testing.T) {
	// Create data shards.
	numData := 10
	numParity := 2
	shardSize := 100

	dataShards := make([][]byte, numData)
	for i := range dataShards {
		dataShards[i] = make([]byte, shardSize)
		for j := range dataShards[i] {
			dataShards[i][j] = byte(i*shardSize + j)
		}
	}

	// Generate parity.
	parity, err := generateFECShards(dataShards, numParity)
	require.NoError(t, err)

	// Simulate packet loss: drop 2 data shards.
	allShards := make([][]byte, numData+numParity)
	for i := range dataShards {
		allShards[i] = make([]byte, shardSize)
		copy(allShards[i], dataShards[i])
	}
	for i, p := range parity {
		allShards[numData+i] = p
	}

	// "Lose" shards 2 and 5.
	allShards[2] = nil
	allShards[5] = nil

	// Recover using RS decoder.
	enc, err := reedsolomon.New(numData, numParity)
	require.NoError(t, err)

	err = enc.Reconstruct(allShards)
	require.NoError(t, err)

	// Verify recovered data matches original.
	assert.Equal(t, dataShards[2], allShards[2])
	assert.Equal(t, dataShards[5], allShards[5])
}

func TestSplitIntoShards(t *testing.T) {
	data := make([]byte, 250)
	for i := range data {
		data[i] = byte(i)
	}

	shards := splitIntoShards(data, 100)
	assert.Len(t, shards, 3)
	assert.Len(t, shards[0], 100)
	assert.Len(t, shards[1], 100)
	assert.Len(t, shards[2], 50) // last shard is shorter

	// Reassemble.
	var reassembled []byte
	for _, s := range shards {
		reassembled = append(reassembled, s...)
	}
	assert.Equal(t, data, reassembled)
}

// collectVideoPackets uses the videoPacketizer to packetize a frame and captures
// the raw packet bytes that would be sent. It does this by calling the
// packetizer's internal methods directly.
func collectVideoPackets(t *testing.T, vp *videoPacketizer, vf videoFrame) [][]byte {
	t.Helper()

	frameIdx := vp.frameIndex
	vp.frameIndex++

	idr := isIDRFrame(vf.data)
	var frameType uint8 = 1
	if idr {
		frameType = 2
	}

	framePayload := buildFramePayload(vf.data, frameType)
	dataShards := splitIntoShards(framePayload, videoPayloadSize)
	totalDataShards := len(dataShards)

	lastPayloadLen := len(framePayload) % videoPayloadSize
	if lastPayloadLen == 0 && totalDataShards > 0 {
		lastPayloadLen = videoPayloadSize
	}
	binary.LittleEndian.PutUint16(dataShards[0][4:6], uint16(lastPayloadLen))

	blocks := splitIntoFECBlocks(dataShards)

	samples := uint32(vf.duration.Seconds() * videoClockRate)
	if samples == 0 {
		samples = videoClockRate / 60
	}
	rtpTimestamp := frameIdx * samples

	var packets [][]byte
	for blockIdx, block := range blocks {
		numDataShards := len(block)
		numParityShards := (numDataShards*fecPercentage + 99) / 100
		if numParityShards == 0 {
			numParityShards = 1
		}

		lastShard := block[numDataShards-1]
		if len(lastShard) < videoPayloadSize {
			padded := make([]byte, videoPayloadSize)
			copy(padded, lastShard)
			block[numDataShards-1] = padded
		}

		parityShards, err := generateFECShards(block, numParityShards)
		require.NoError(t, err)

		globalShardOffset := 0
		for i := 0; i < blockIdx; i++ {
			globalShardOffset += len(blocks[i])
		}

		multiFecFlags := uint8(0x10)
		multiFecBlocks := uint8((blockIdx << 4) | ((len(blocks) - 1) << 6))

		for i, shard := range block {
			var flags uint8 = nvVideoFlagContainsPicData
			globalIdx := globalShardOffset + i
			if globalIdx == 0 {
				flags |= nvVideoFlagSOF
			}
			if globalIdx == totalDataShards-1 {
				flags |= nvVideoFlagEOF
			}
			fecInfo := uint32((i << 22) | (numDataShards << 12) | fecPercentage)
			pkt := vp.buildVideoPacket(rtpTimestamp, frameIdx, uint32(globalIdx), flags, 0, multiFecFlags, multiFecBlocks, fecInfo, shard)
			packets = append(packets, pkt)
		}

		for i, shard := range parityShards {
			shardIdx := numDataShards + i
			fecInfo := uint32((shardIdx << 22) | (numDataShards << 12) | fecPercentage)
			pkt := vp.buildVideoPacket(rtpTimestamp, frameIdx, uint32(globalShardOffset+shardIdx), 0, 0, multiFecFlags, multiFecBlocks, fecInfo, shard)
			packets = append(packets, pkt)
		}
	}

	return packets
}
