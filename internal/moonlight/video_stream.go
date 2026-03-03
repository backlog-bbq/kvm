package moonlight

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/klauspost/reedsolomon"
)

const (
	// videoPayloadType is the RTP payload type for H.264 (dynamic, 96-127 range).
	videoPayloadType = 96
	// videoClockRate is the standard RTP clock rate for video (90kHz).
	videoClockRate = 90000
	// videoSSRC is the fixed SSRC for the video stream.
	videoSSRC = 0x53535243

	// videoHeaderSize is the total overhead before payload data in each packet:
	// 12 (RTP header) + 4 (reserved zeros) + 16 (NV_VIDEO_PACKET) = 32 bytes.
	videoHeaderSize = 32
	// videoMTU is the target UDP packet size (fits in Ethernet MTU).
	videoMTU = 1400
	// videoPayloadSize is the max payload per packet after headers.
	videoPayloadSize = videoMTU - videoHeaderSize // 1368 bytes

	// fecPercentage is the FEC overhead ratio (20% = Sunshine default).
	fecPercentage = 20
	// maxDataShardsPerBlock is the max data shards in a single FEC block.
	// Derived from: (255 * 100) / (100 + fecPercentage)
	maxDataShardsPerBlock = 212
	// maxFECBlocks is the maximum number of FEC blocks per frame (2 bits).
	maxFECBlocks = 4
)

// NV_VIDEO_PACKET flags.
const (
	nvVideoFlagSOF              = 0x04 // Start of frame
	nvVideoFlagEOF              = 0x02 // End of frame
	nvVideoFlagContainsPicData  = 0x01 // Contains picture data (not FEC parity)
)

// videoPacketizer holds state for the custom Moonlight video packetizer.
type videoPacketizer struct {
	frameIndex uint32
	seqNum     uint16
}

// runVideoStream reads H.264 frames from videoFrameCh and sends them as
// Moonlight-format RTP packets to the active client's video endpoint.
func (s *Server) runVideoStream() {
	log.Info().Int("port", VideoPort).Msg("video RTP sender ready")

	var (
		conn     *net.UDPConn
		vp       videoPacketizer
		lastDest string
	)

	keepAliveTicker := time.NewTicker(500 * time.Millisecond)
	defer keepAliveTicker.Stop()

	lastFrameTime := time.Now()

	for {
		select {
		case <-s.ctx.Done():
			if conn != nil {
				conn.Close()
			}
			return

		case <-keepAliveTicker.C:
			if conn != nil && time.Since(lastFrameTime) > 500*time.Millisecond {
				keepVideoAlive(conn, vp.seqNum)
			}

		case vf := <-s.videoFrameCh:
			sess := s.getSession()
			if sess == nil {
				continue
			}

			dest := fmt.Sprintf("%s:%d", sess.ClientIP.String(), sess.VideoPort)

			// (Re)open the UDP socket when the destination changes.
			if dest != lastDest || conn == nil {
				if conn != nil {
					conn.Close()
				}
				var err error
				conn, err = openVideoUDP(dest)
				if err != nil {
					log.Warn().Err(err).Str("dest", dest).Msg("failed to open video UDP socket")
					conn = nil
					continue
				}
				lastDest = dest
				vp = videoPacketizer{} // reset state
				log.Info().Str("dest", dest).Msg("video RTP stream connected")
			}

			lastFrameTime = time.Now()
			if err := vp.sendFrame(conn, vf); err != nil {
				log.Warn().Err(err).Msg("video send error")
			}
		}
	}
}

// openVideoUDP creates a connected UDP socket to the Moonlight client's video port.
func openVideoUDP(dest string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return nil, fmt.Errorf("moonlight: resolve video UDP %q: %w", dest, err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("moonlight: dial video UDP %q: %w", dest, err)
	}
	return conn, nil
}

// sendFrame packetizes a raw H.264 frame using the Moonlight NV_VIDEO_PACKET
// format with Reed-Solomon FEC and sends all packets over the UDP connection.
func (vp *videoPacketizer) sendFrame(conn *net.UDPConn, vf videoFrame) error {
	frameIdx := vp.frameIndex
	vp.frameIndex++

	idr := isIDRFrame(vf.data)
	var frameType uint8 = 1 // P-frame
	if idr {
		frameType = 2 // IDR
	}

	// Build the frame payload: 8-byte frame header + H.264 data.
	framePayload := buildFramePayload(vf.data, frameType)

	// Split into data shards of videoPayloadSize bytes each.
	dataShards := splitIntoShards(framePayload, videoPayloadSize)
	totalDataShards := len(dataShards)

	// Compute last payload length before padding (for frame header).
	lastPayloadLen := len(framePayload) % videoPayloadSize
	if lastPayloadLen == 0 && totalDataShards > 0 {
		lastPayloadLen = videoPayloadSize
	}

	// Update the frame header's lastPayloadLen field now that we know it.
	binary.LittleEndian.PutUint16(dataShards[0][4:6], uint16(lastPayloadLen))

	// Split data shards into FEC blocks.
	blocks := splitIntoFECBlocks(dataShards)

	// RTP timestamp for this frame.
	samples := uint32(vf.duration.Seconds() * videoClockRate)
	if samples == 0 {
		samples = videoClockRate / 60
	}
	rtpTimestamp := frameIdx * samples

	// Process each FEC block.
	for blockIdx, block := range blocks {
		numDataShards := len(block)
		numParityShards := (numDataShards*fecPercentage + 99) / 100
		if numParityShards == 0 {
			numParityShards = 1
		}

		// Pad last data shard to videoPayloadSize for FEC alignment.
		lastShard := block[numDataShards-1]
		if len(lastShard) < videoPayloadSize {
			padded := make([]byte, videoPayloadSize)
			copy(padded, lastShard)
			block[numDataShards-1] = padded
		}

		// Generate FEC parity shards.
		parityShards, err := generateFECShards(block, numParityShards)
		if err != nil {
			log.Warn().Err(err).Int("block", blockIdx).Msg("FEC encoding failed, sending without parity")
			parityShards = nil
		}

		// Compute the global shard index offset for this block.
		globalShardOffset := 0
		for i := 0; i < blockIdx; i++ {
			globalShardOffset += len(blocks[i])
		}

		// fecInfo encoding: (shardIndex << 22) | (dataShardCount << 12) | fecPercentage
		// multiFecBlocks: (blockIndex << 4) | ((totalBlocks-1) << 6)
		multiFecFlags := uint8(0x10)
		multiFecBlocks := uint8((blockIdx << 4) | ((len(blocks) - 1) << 6))

		// Send data shards.
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

			pkt := vp.buildVideoPacket(
				rtpTimestamp, frameIdx, uint32(globalIdx),
				flags, 0, multiFecFlags, multiFecBlocks, fecInfo,
				shard,
			)
			if _, err := conn.Write(pkt); err != nil {
				return fmt.Errorf("moonlight: write video data shard: %w", err)
			}
		}

		// Send parity shards.
		for i, shard := range parityShards {
			shardIdx := numDataShards + i
			fecInfo := uint32((shardIdx << 22) | (numDataShards << 12) | fecPercentage)

			pkt := vp.buildVideoPacket(
				rtpTimestamp, frameIdx, uint32(globalShardOffset+shardIdx),
				0, 0, multiFecFlags, multiFecBlocks, fecInfo,
				shard,
			)
			if _, err := conn.Write(pkt); err != nil {
				return fmt.Errorf("moonlight: write video parity shard: %w", err)
			}
		}
	}

	return nil
}

// buildFramePayload prepends the 8-byte video_short_frame_header_t to the H.264 data.
//
// Frame header layout:
//
//	offset 0: uint8  headerType = 0x01
//	offset 1: uint16 frame_processing_latency (LE, in 1/10 ms)
//	offset 3: uint8  frameType  (1=P-frame, 2=IDR)
//	offset 4: uint16 lastPayloadLen (LE) — filled in later by sendFrame
//	offset 6: uint8[2] reserved zeros
func buildFramePayload(h264Data []byte, frameType uint8) []byte {
	header := make([]byte, 8)
	header[0] = 0x01      // headerType
	header[1] = 0         // frame_processing_latency low byte
	header[2] = 0         // frame_processing_latency high byte
	header[3] = frameType // 1=P-frame, 2=IDR
	// header[4:6] = lastPayloadLen — set later
	// header[6:8] = reserved zeros

	payload := make([]byte, 8+len(h264Data))
	copy(payload, header)
	copy(payload[8:], h264Data)
	return payload
}

// splitIntoShards splits data into chunks of shardSize bytes.
// The last chunk may be smaller than shardSize.
func splitIntoShards(data []byte, shardSize int) [][]byte {
	if len(data) == 0 {
		return [][]byte{make([]byte, 0)}
	}
	n := (len(data) + shardSize - 1) / shardSize
	shards := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := i * shardSize
		end := start + shardSize
		if end > len(data) {
			end = len(data)
		}
		shard := make([]byte, end-start)
		copy(shard, data[start:end])
		shards[i] = shard
	}
	return shards
}

// splitIntoFECBlocks splits data shards into up to maxFECBlocks blocks,
// each containing at most maxDataShardsPerBlock shards.
func splitIntoFECBlocks(shards [][]byte) [][][]byte {
	if len(shards) <= maxDataShardsPerBlock {
		return [][][]byte{shards}
	}

	numBlocks := (len(shards) + maxDataShardsPerBlock - 1) / maxDataShardsPerBlock
	if numBlocks > maxFECBlocks {
		numBlocks = maxFECBlocks
	}

	shardsPerBlock := (len(shards) + numBlocks - 1) / numBlocks
	blocks := make([][][]byte, 0, numBlocks)
	for i := 0; i < len(shards); i += shardsPerBlock {
		end := i + shardsPerBlock
		if end > len(shards) {
			end = len(shards)
		}
		blocks = append(blocks, shards[i:end])
	}
	return blocks
}

// generateFECShards creates Reed-Solomon parity shards for the given data shards.
// All data shards must be the same length (caller must pad).
func generateFECShards(dataShards [][]byte, numParity int) ([][]byte, error) {
	enc, err := reedsolomon.New(len(dataShards), numParity)
	if err != nil {
		return nil, fmt.Errorf("moonlight: reedsolomon.New(%d, %d): %w", len(dataShards), numParity, err)
	}

	// Build the full shard matrix: data shards + empty parity shards.
	shardSize := len(dataShards[0])
	allShards := make([][]byte, len(dataShards)+numParity)
	for i, s := range dataShards {
		allShards[i] = s
	}
	for i := 0; i < numParity; i++ {
		allShards[len(dataShards)+i] = make([]byte, shardSize)
	}

	if err := enc.Encode(allShards); err != nil {
		return nil, fmt.Errorf("moonlight: FEC encode: %w", err)
	}

	return allShards[len(dataShards):], nil
}

// buildVideoPacket constructs a single Moonlight video packet with the format:
//
//	[12B RTP header] [4B reserved zeros] [16B NV_VIDEO_PACKET] [payload]
func (vp *videoPacketizer) buildVideoPacket(
	rtpTimestamp, frameIndex, streamPacketIndex uint32,
	flags, extraFlags, multiFecFlags, multiFecBlocks uint8,
	fecInfo uint32,
	payload []byte,
) []byte {
	pkt := make([]byte, videoHeaderSize+len(payload))

	// RTP header (12 bytes).
	pkt[0] = 0x80 // V=2, P=0, X=0, CC=0
	pkt[1] = videoPayloadType & 0x7F
	binary.BigEndian.PutUint16(pkt[2:4], vp.seqNum)
	vp.seqNum++
	binary.BigEndian.PutUint32(pkt[4:8], rtpTimestamp)
	binary.BigEndian.PutUint32(pkt[8:12], videoSSRC)

	// Reserved zeros (4 bytes at offset 12).
	// pkt[12:16] already zero

	// NV_VIDEO_PACKET (16 bytes at offset 16).
	nv := pkt[16:32]
	binary.LittleEndian.PutUint32(nv[0:4], streamPacketIndex<<8)
	binary.LittleEndian.PutUint32(nv[4:8], frameIndex)
	nv[8] = flags
	nv[9] = extraFlags
	nv[10] = multiFecFlags
	nv[11] = multiFecBlocks
	binary.LittleEndian.PutUint32(nv[12:16], fecInfo)

	// Payload.
	copy(pkt[videoHeaderSize:], payload)

	return pkt
}

// isIDRFrame returns true if any NALU in the H.264 frame is an IDR slice (type 5)
// or a SPS (type 7, which accompanies IDR frames).
func isIDRFrame(frame []byte) bool {
	for i := 0; i+3 < len(frame); i++ {
		if frame[i] == 0 && frame[i+1] == 0 {
			start := -1
			if frame[i+2] == 1 {
				start = i + 3
			} else if i+4 < len(frame) && frame[i+2] == 0 && frame[i+3] == 1 {
				start = i + 4
			}
			if start >= 0 && start < len(frame) {
				naluType := frame[start] & 0x1F
				if naluType == 5 || naluType == 7 { // IDR slice or SPS
					return true
				}
			}
		}
	}
	return false
}

// keepVideoAlive sends a minimal keep-alive RTP packet when no frames are available.
func keepVideoAlive(conn *net.UDPConn, seqNum uint16) {
	pkt := make([]byte, 12)
	pkt[0] = 0x80
	pkt[1] = videoPayloadType & 0x7F
	binary.BigEndian.PutUint16(pkt[2:4], seqNum)
	binary.BigEndian.PutUint32(pkt[4:8], uint32(time.Now().UnixNano()/1000*90/1000))
	binary.BigEndian.PutUint32(pkt[8:12], videoSSRC)
	_, _ = conn.Write(pkt)
}
