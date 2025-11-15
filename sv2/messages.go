package sv2

import (
	"errors"
	"fmt"
)

// Message is the interface that all Stratum V2 messages implement
type Message interface {
	Type() uint8
	ToBytes() ([]byte, error)
	ToFrame() (*Frame, error)
}

// SetupConnection initiates the connection. This MUST be the first message sent
// by the client on the newly opened connection.
type SetupConnection struct {
	Protocol       uint8  // 0=Mining, 1=JobNegotiation, 2=TemplateDistribution, 3=JobDistribution
	MinVersion     uint16 // Minimum protocol version supported
	MaxVersion     uint16 // Maximum protocol version supported
	Flags          uint32 // Optional protocol feature flags
	EndpointHost   string // Hostname or IP address
	EndpointPort   uint16 // Port number
	Vendor         string // Device vendor/manufacturer
	HardwareVersion string // Hardware version
	Firmware       string // Firmware version
	DeviceID       string // Device identifier
}

func (m *SetupConnection) Type() uint8 { return MsgTypeSetupConnection }

func (m *SetupConnection) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 256)
	result = append(result, U8(m.Protocol)...)
	result = append(result, U16(m.MinVersion)...)
	result = append(result, U16(m.MaxVersion)...)
	result = append(result, U32(m.Flags)...)

	endpointHost, err := STR0_255(m.EndpointHost)
	if err != nil {
		return nil, fmt.Errorf("endpoint_host: %w", err)
	}
	result = append(result, endpointHost...)
	result = append(result, U16(m.EndpointPort)...)

	vendor, err := STR0_255(m.Vendor)
	if err != nil {
		return nil, fmt.Errorf("vendor: %w", err)
	}
	result = append(result, vendor...)

	hwVersion, err := STR0_255(m.HardwareVersion)
	if err != nil {
		return nil, fmt.Errorf("hardware_version: %w", err)
	}
	result = append(result, hwVersion...)

	firmware, err := STR0_255(m.Firmware)
	if err != nil {
		return nil, fmt.Errorf("firmware: %w", err)
	}
	result = append(result, firmware...)

	deviceID, err := STR0_255(m.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("device_id: %w", err)
	}
	result = append(result, deviceID...)

	return result, nil
}

func (m *SetupConnection) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSetupConnection(data []byte) (*SetupConnection, error) {
	if len(data) < 9 {
		return nil, errors.New("insufficient data")
	}

	msg := &SetupConnection{}
	offset := 0

	msg.Protocol = data[offset]
	offset++

	var err error
	msg.MinVersion, err = ReadU16(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 2

	msg.MaxVersion, err = ReadU16(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 2

	msg.Flags, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 4

	var n int
	msg.EndpointHost, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.EndpointPort, err = ReadU16(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 2

	msg.Vendor, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.HardwareVersion, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.Firmware, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.DeviceID, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// SetupConnectionSuccess is the response to SetupConnection if the server accepts the connection
type SetupConnectionSuccess struct {
	UsedVersion uint16 // Selected protocol version
	Flags       uint32 // Server-supported feature flags
}

func (m *SetupConnectionSuccess) Type() uint8 { return MsgTypeSetupConnectionSuccess }

func (m *SetupConnectionSuccess) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 6)
	result = append(result, U16(m.UsedVersion)...)
	result = append(result, U32(m.Flags)...)
	return result, nil
}

func (m *SetupConnectionSuccess) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSetupConnectionSuccess(data []byte) (*SetupConnectionSuccess, error) {
	if len(data) < 6 {
		return nil, errors.New("insufficient data")
	}

	usedVersion, err := ReadU16(data[0:2])
	if err != nil {
		return nil, err
	}

	flags, err := ReadU32(data[2:6])
	if err != nil {
		return nil, err
	}

	return &SetupConnectionSuccess{
		UsedVersion: usedVersion,
		Flags:       flags,
	}, nil
}

// SetupConnectionError is sent when protocol version negotiation fails
type SetupConnectionError struct {
	Flags     uint32 // Flags indicating features causing an error
	ErrorCode string // Human-readable error code
}

func (m *SetupConnectionError) Type() uint8 { return MsgTypeSetupConnectionError }

func (m *SetupConnectionError) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.Flags)...)

	errorCode, err := STR0_255(m.ErrorCode)
	if err != nil {
		return nil, fmt.Errorf("error_code: %w", err)
	}
	result = append(result, errorCode...)

	return result, nil
}

func (m *SetupConnectionError) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSetupConnectionError(data []byte) (*SetupConnectionError, error) {
	if len(data) < 5 {
		return nil, errors.New("insufficient data")
	}

	flags, err := ReadU32(data[0:4])
	if err != nil {
		return nil, err
	}

	errorCode, _, err := ReadSTR0_255(data[4:])
	if err != nil {
		return nil, err
	}

	return &SetupConnectionError{
		Flags:     flags,
		ErrorCode: errorCode,
	}, nil
}

// OpenStandardMiningChannel requests to open a standard channel to the upstream node
type OpenStandardMiningChannel struct {
	ReqID            uint32 // Client-specified request identifier
	UserIdentity     string // User identification string
	NominalHashRate  uint32 // Expected hash rate in h/s
	MaxTarget        []byte // Maximum target (32 bytes)
}

func (m *OpenStandardMiningChannel) Type() uint8 { return MsgTypeOpenStandardMiningChannel }

func (m *OpenStandardMiningChannel) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 128)
	result = append(result, U32(m.ReqID)...)

	userIdentity, err := STR0_255(m.UserIdentity)
	if err != nil {
		return nil, fmt.Errorf("user_identity: %w", err)
	}
	result = append(result, userIdentity...)
	result = append(result, U32(m.NominalHashRate)...)

	maxTarget, err := U256(m.MaxTarget)
	if err != nil {
		return nil, fmt.Errorf("max_target: %w", err)
	}
	result = append(result, maxTarget...)

	return result, nil
}

func (m *OpenStandardMiningChannel) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseOpenStandardMiningChannel(data []byte) (*OpenStandardMiningChannel, error) {
	if len(data) < 37 {
		return nil, errors.New("insufficient data")
	}

	msg := &OpenStandardMiningChannel{}
	offset := 0

	var err error
	msg.ReqID, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 4

	var n int
	msg.UserIdentity, n, err = ReadSTR0_255(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.NominalHashRate, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 4

	msg.MaxTarget, err = ReadU256(data[offset:])
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// OpenStandardMiningChannelSuccess is the response for opening a standard channel, if successful
type OpenStandardMiningChannelSuccess struct {
	ReqID            uint32 // Request ID from OpenStandardMiningChannel
	ChannelID        uint32 // Newly assigned channel identifier
	Target           []byte // Initial target (32 bytes)
	ExtranoncePrefix []byte // Extranonce prefix bytes (0-32 bytes)
	GroupChannelID   uint32 // Group channel this channel belongs to
}

func (m *OpenStandardMiningChannelSuccess) Type() uint8 {
	return MsgTypeOpenStandardMiningChannelSuccess
}

func (m *OpenStandardMiningChannelSuccess) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 128)
	result = append(result, U32(m.ReqID)...)
	result = append(result, U32(m.ChannelID)...)

	target, err := U256(m.Target)
	if err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	result = append(result, target...)

	extranoncePrefix, err := B0_32(m.ExtranoncePrefix)
	if err != nil {
		return nil, fmt.Errorf("extranonce_prefix: %w", err)
	}
	result = append(result, extranoncePrefix...)
	result = append(result, U32(m.GroupChannelID)...)

	return result, nil
}

func (m *OpenStandardMiningChannelSuccess) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseOpenStandardMiningChannelSuccess(data []byte) (*OpenStandardMiningChannelSuccess, error) {
	if len(data) < 41 {
		return nil, errors.New("insufficient data")
	}

	msg := &OpenStandardMiningChannelSuccess{}
	offset := 0

	var err error
	msg.ReqID, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 4

	msg.ChannelID, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 4

	msg.Target, err = ReadU256(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += 32

	var n int
	msg.ExtranoncePrefix, n, err = ReadB0_32(data[offset:])
	if err != nil {
		return nil, err
	}
	offset += n

	msg.GroupChannelID, err = ReadU32(data[offset:])
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// OpenStandardMiningChannelError is sent when opening a standard channel fails
type OpenStandardMiningChannelError struct {
	ReqID     uint32 // Request ID from OpenStandardMiningChannel
	ErrorCode string // Human-readable error code
}

func (m *OpenStandardMiningChannelError) Type() uint8 {
	return MsgTypeOpenStandardMiningChannelError
}

func (m *OpenStandardMiningChannelError) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.ReqID)...)

	errorCode, err := STR0_255(m.ErrorCode)
	if err != nil {
		return nil, fmt.Errorf("error_code: %w", err)
	}
	result = append(result, errorCode...)

	return result, nil
}

func (m *OpenStandardMiningChannelError) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseOpenStandardMiningChannelError(data []byte) (*OpenStandardMiningChannelError, error) {
	if len(data) < 5 {
		return nil, errors.New("insufficient data")
	}

	reqID, err := ReadU32(data[0:4])
	if err != nil {
		return nil, err
	}

	errorCode, _, err := ReadSTR0_255(data[4:])
	if err != nil {
		return nil, err
	}

	return &OpenStandardMiningChannelError{
		ReqID:     reqID,
		ErrorCode: errorCode,
	}, nil
}

// SubmitSharesStandard is sent by client to submit mining results
type SubmitSharesStandard struct {
	ChannelID      uint32 // Channel identifier
	SequenceNumber uint32 // Unique sequential identifier within the channel
	JobID          uint32 // Job identifier from NewMiningJob
	Nonce          uint32 // Nonce leading to the hash being submitted
	NTime          uint32 // The nTime field in the block header
	Version        uint32 // Full nVersion field
}

func (m *SubmitSharesStandard) Type() uint8 { return MsgTypeSubmitSharesStandard }

func (m *SubmitSharesStandard) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 24)
	result = append(result, U32(m.ChannelID)...)
	result = append(result, U32(m.SequenceNumber)...)
	result = append(result, U32(m.JobID)...)
	result = append(result, U32(m.Nonce)...)
	result = append(result, U32(m.NTime)...)
	result = append(result, U32(m.Version)...)
	return result, nil
}

func (m *SubmitSharesStandard) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSubmitSharesStandard(data []byte) (*SubmitSharesStandard, error) {
	if len(data) < 24 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	sequenceNumber, _ := ReadU32(data[4:8])
	jobID, _ := ReadU32(data[8:12])
	nonce, _ := ReadU32(data[12:16])
	ntime, _ := ReadU32(data[16:20])
	version, _ := ReadU32(data[20:24])

	return &SubmitSharesStandard{
		ChannelID:      channelID,
		SequenceNumber: sequenceNumber,
		JobID:          jobID,
		Nonce:          nonce,
		NTime:          ntime,
		Version:        version,
	}, nil
}

// SubmitSharesSuccess is the response to SubmitSharesStandard, accepting results
type SubmitSharesSuccess struct {
	ChannelID               uint32 // Channel identifier
	LastSequenceNumber      uint32 // Most recent sequence number with correct result
	NewSubmitsAcceptedCount uint32 // Count of new submits acknowledged
	NewSharesSum            uint32 // Sum of shares acknowledged
}

func (m *SubmitSharesSuccess) Type() uint8 { return MsgTypeSubmitSharesSuccess }

func (m *SubmitSharesSuccess) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 16)
	result = append(result, U32(m.ChannelID)...)
	result = append(result, U32(m.LastSequenceNumber)...)
	result = append(result, U32(m.NewSubmitsAcceptedCount)...)
	result = append(result, U32(m.NewSharesSum)...)
	return result, nil
}

func (m *SubmitSharesSuccess) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSubmitSharesSuccess(data []byte) (*SubmitSharesSuccess, error) {
	if len(data) < 16 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	lastSeqNum, _ := ReadU32(data[4:8])
	newSubmitsAccepted, _ := ReadU32(data[8:12])
	newSharesSum, _ := ReadU32(data[12:16])

	return &SubmitSharesSuccess{
		ChannelID:               channelID,
		LastSequenceNumber:      lastSeqNum,
		NewSubmitsAcceptedCount: newSubmitsAccepted,
		NewSharesSum:            newSharesSum,
	}, nil
}

// SubmitSharesError indicates an error with submitted shares
type SubmitSharesError struct {
	ChannelID      uint32 // Channel identifier
	SequenceNumber uint32 // Sequence number of the failed submit
	ErrorCode      string // Human-readable error code
}

func (m *SubmitSharesError) Type() uint8 { return MsgTypeSubmitSharesError }

func (m *SubmitSharesError) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.ChannelID)...)
	result = append(result, U32(m.SequenceNumber)...)

	errorCode, err := STR0_255(m.ErrorCode)
	if err != nil {
		return nil, fmt.Errorf("error_code: %w", err)
	}
	result = append(result, errorCode...)

	return result, nil
}

func (m *SubmitSharesError) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSubmitSharesError(data []byte) (*SubmitSharesError, error) {
	if len(data) < 9 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	sequenceNumber, _ := ReadU32(data[4:8])
	errorCode, _, err := ReadSTR0_255(data[8:])
	if err != nil {
		return nil, err
	}

	return &SubmitSharesError{
		ChannelID:      channelID,
		SequenceNumber: sequenceNumber,
		ErrorCode:      errorCode,
	}, nil
}

// NewMiningJob provides an updated mining job to the client
type NewMiningJob struct {
	ChannelID  uint32 // Channel identifier
	JobID      uint32 // Server's identification of the mining job
	FutureJob  bool   // True if job is for future SetNewPrevHash
	Version    uint32 // Valid version field
	MerkleRoot []byte // Merkle root (32 bytes)
}

func (m *NewMiningJob) Type() uint8 { return MsgTypeNewMiningJob }

func (m *NewMiningJob) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.ChannelID)...)
	result = append(result, U32(m.JobID)...)
	result = append(result, BOOL(m.FutureJob)...)
	result = append(result, U32(m.Version)...)

	merkleRoot, err := U256(m.MerkleRoot)
	if err != nil {
		return nil, fmt.Errorf("merkle_root: %w", err)
	}
	result = append(result, merkleRoot...)

	return result, nil
}

func (m *NewMiningJob) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseNewMiningJob(data []byte) (*NewMiningJob, error) {
	if len(data) < 41 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	jobID, _ := ReadU32(data[4:8])
	futureJob, _ := ReadBOOL(data[8:9])
	version, _ := ReadU32(data[9:13])
	merkleRoot, _ := ReadU256(data[13:45])

	return &NewMiningJob{
		ChannelID:  channelID,
		JobID:      jobID,
		FutureJob:  futureJob,
		Version:    version,
		MerkleRoot: merkleRoot,
	}, nil
}

// SetNewPrevHash distributes prevhash when a new block is detected
type SetNewPrevHash struct {
	ChannelID uint32 // Channel or group channel identifier
	JobID     uint32 // Job ID to use with this prevhash
	PrevHash  []byte // Previous block's hash (32 bytes)
	MinNTime  uint32 // Smallest nTime value available for hashing
	NBits     uint32 // Difficulty target
}

func (m *SetNewPrevHash) Type() uint8 { return MsgTypeSetNewPrevHash }

func (m *SetNewPrevHash) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.ChannelID)...)
	result = append(result, U32(m.JobID)...)

	prevHash, err := U256(m.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("prev_hash: %w", err)
	}
	result = append(result, prevHash...)
	result = append(result, U32(m.MinNTime)...)
	result = append(result, U32(m.NBits)...)

	return result, nil
}

func (m *SetNewPrevHash) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSetNewPrevHash(data []byte) (*SetNewPrevHash, error) {
	if len(data) < 48 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	jobID, _ := ReadU32(data[4:8])
	prevHash, _ := ReadU256(data[8:40])
	minNTime, _ := ReadU32(data[40:44])
	nbits, _ := ReadU32(data[44:48])

	return &SetNewPrevHash{
		ChannelID: channelID,
		JobID:     jobID,
		PrevHash:  prevHash,
		MinNTime:  minNTime,
		NBits:     nbits,
	}, nil
}

// SetTarget sets a new mining target for the channel
type SetTarget struct {
	ChannelID uint32 // Channel identifier
	MaxTarget []byte // Maximum target (32 bytes)
}

func (m *SetTarget) Type() uint8 { return MsgTypeSetTarget }

func (m *SetTarget) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 36)
	result = append(result, U32(m.ChannelID)...)

	maxTarget, err := U256(m.MaxTarget)
	if err != nil {
		return nil, fmt.Errorf("max_target: %w", err)
	}
	result = append(result, maxTarget...)

	return result, nil
}

func (m *SetTarget) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseSetTarget(data []byte) (*SetTarget, error) {
	if len(data) < 36 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	maxTarget, _ := ReadU256(data[4:36])

	return &SetTarget{
		ChannelID: channelID,
		MaxTarget: maxTarget,
	}, nil
}

// CloseChannel is sent to end operation on a channel
type CloseChannel struct {
	ChannelID  uint32 // Channel identifier
	ReasonCode string // Reason for closing
}

func (m *CloseChannel) Type() uint8 { return MsgTypeCloseChannel }

func (m *CloseChannel) ToBytes() ([]byte, error) {
	result := make([]byte, 0, 64)
	result = append(result, U32(m.ChannelID)...)

	reasonCode, err := STR0_255(m.ReasonCode)
	if err != nil {
		return nil, fmt.Errorf("reason_code: %w", err)
	}
	result = append(result, reasonCode...)

	return result, nil
}

func (m *CloseChannel) ToFrame() (*Frame, error) {
	payload, err := m.ToBytes()
	if err != nil {
		return nil, err
	}
	return CreateFrame(0, m.Type(), payload)
}

func ParseCloseChannel(data []byte) (*CloseChannel, error) {
	if len(data) < 5 {
		return nil, errors.New("insufficient data")
	}

	channelID, _ := ReadU32(data[0:4])
	reasonCode, _, err := ReadSTR0_255(data[4:])
	if err != nil {
		return nil, err
	}

	return &CloseChannel{
		ChannelID:  channelID,
		ReasonCode: reasonCode,
	}, nil
}

// ParseMessage parses a message from a frame based on its type
func ParseMessage(frame *Frame) (Message, error) {
	switch frame.MessageType {
	case MsgTypeSetupConnection:
		return ParseSetupConnection(frame.Payload)
	case MsgTypeSetupConnectionSuccess:
		return ParseSetupConnectionSuccess(frame.Payload)
	case MsgTypeSetupConnectionError:
		return ParseSetupConnectionError(frame.Payload)
	case MsgTypeOpenStandardMiningChannel:
		return ParseOpenStandardMiningChannel(frame.Payload)
	case MsgTypeOpenStandardMiningChannelSuccess:
		return ParseOpenStandardMiningChannelSuccess(frame.Payload)
	case MsgTypeOpenStandardMiningChannelError:
		return ParseOpenStandardMiningChannelError(frame.Payload)
	case MsgTypeSubmitSharesStandard:
		return ParseSubmitSharesStandard(frame.Payload)
	case MsgTypeSubmitSharesSuccess:
		return ParseSubmitSharesSuccess(frame.Payload)
	case MsgTypeSubmitSharesError:
		return ParseSubmitSharesError(frame.Payload)
	case MsgTypeNewMiningJob:
		return ParseNewMiningJob(frame.Payload)
	case MsgTypeSetNewPrevHash:
		return ParseSetNewPrevHash(frame.Payload)
	case MsgTypeSetTarget:
		return ParseSetTarget(frame.Payload)
	case MsgTypeCloseChannel:
		return ParseCloseChannel(frame.Payload)
	default:
		return nil, fmt.Errorf("unsupported message type: 0x%02x", frame.MessageType)
	}
}
