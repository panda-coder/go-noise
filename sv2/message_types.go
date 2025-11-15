package sv2

import (
	"errors"
	"fmt"
)

// Message type constants for Stratum V2 protocol
const (
	// Common messages
	MsgTypeSetupConnection              = 0x00
	MsgTypeSetupConnectionSuccess       = 0x01
	MsgTypeSetupConnectionError         = 0x02
	MsgTypeChannelEndpointChanged       = 0x03

	// Mining protocol messages
	MsgTypeOpenStandardMiningChannel        = 0x10
	MsgTypeOpenStandardMiningChannelSuccess = 0x11
	MsgTypeOpenStandardMiningChannelError   = 0x12
	MsgTypeOpenExtendedMiningChannel        = 0x13
	MsgTypeOpenExtendedMiningChannelSuccess = 0x14
	MsgTypeOpenExtendedMiningChannelError   = 0x15
	MsgTypeUpdateChannel                    = 0x16
	MsgTypeUpdateChannelError               = 0x17
	MsgTypeCloseChannel                     = 0x18
	MsgTypeSetExtranoncePrefix              = 0x19
	MsgTypeSubmitSharesStandard             = 0x1A
	MsgTypeSubmitSharesExtended             = 0x1B
	MsgTypeSubmitSharesSuccess              = 0x1C
	MsgTypeSubmitSharesError                = 0x1D
	MsgTypeNewMiningJob                     = 0x1E
	MsgTypeNewExtendedMiningJob             = 0x1F
	MsgTypeSetNewPrevHash                   = 0x20
	MsgTypeSetTarget                        = 0x21
	MsgTypeSetCustomMiningJob               = 0x22
	MsgTypeSetCustomMiningJobSuccess        = 0x23
	MsgTypeSetCustomMiningJobError          = 0x24
	MsgTypeReconnect                        = 0x25
	MsgTypeSetGroupChannel                  = 0x26

	// Job negotiation protocol messages
	MsgTypeAllocateMiningJobToken        = 0x50
	MsgTypeAllocateMiningJobTokenSuccess = 0x51
	MsgTypeAllocateMiningJobTokenError   = 0x52
	MsgTypeIdentifyTransactions          = 0x53
	MsgTypeIdentifyTransactionsSuccess   = 0x54
	MsgTypeProvideMissingTransactions    = 0x55
	MsgTypeProvideMissingTransactionsSuccess = 0x56

	// Template distribution protocol messages
	MsgTypeCoinbaseOutputDataSize       = 0x70
	MsgTypeNewTemplate                  = 0x71
	MsgTypeSetNewPrevHashTDP            = 0x72
	MsgTypeRequestTransactionData       = 0x73
	MsgTypeRequestTransactionDataSuccess = 0x74
	MsgTypeRequestTransactionDataError  = 0x75
	MsgTypeSubmitSolution               = 0x76
)

// Channel message bit flag
const ChannelMessageBit = 0x80

// Message type info
type MessageTypeInfo struct {
	Type          uint8
	Name          string
	IsChannelMsg  bool
}

// messageTypeMap maps message types to their info
var messageTypeMap = map[uint8]MessageTypeInfo{
	MsgTypeSetupConnection:                      {MsgTypeSetupConnection, "SetupConnection", false},
	MsgTypeSetupConnectionSuccess:               {MsgTypeSetupConnectionSuccess, "SetupConnectionSuccess", false},
	MsgTypeSetupConnectionError:                 {MsgTypeSetupConnectionError, "SetupConnectionError", false},
	MsgTypeChannelEndpointChanged:               {MsgTypeChannelEndpointChanged, "ChannelEndpointChanged", true},
	MsgTypeOpenStandardMiningChannel:            {MsgTypeOpenStandardMiningChannel, "OpenStandardMiningChannel", false},
	MsgTypeOpenStandardMiningChannelSuccess:     {MsgTypeOpenStandardMiningChannelSuccess, "OpenStandardMiningChannelSuccess", false},
	MsgTypeOpenStandardMiningChannelError:       {MsgTypeOpenStandardMiningChannelError, "OpenStandardMiningChannelError", false},
	MsgTypeOpenExtendedMiningChannel:            {MsgTypeOpenExtendedMiningChannel, "OpenExtendedMiningChannel", false},
	MsgTypeOpenExtendedMiningChannelSuccess:     {MsgTypeOpenExtendedMiningChannelSuccess, "OpenExtendedMiningChannelSuccess", false},
	MsgTypeOpenExtendedMiningChannelError:       {MsgTypeOpenExtendedMiningChannelError, "OpenExtendedMiningChannelError", false},
	MsgTypeUpdateChannel:                        {MsgTypeUpdateChannel, "UpdateChannel", true},
	MsgTypeUpdateChannelError:                   {MsgTypeUpdateChannelError, "UpdateChannelError", true},
	MsgTypeCloseChannel:                         {MsgTypeCloseChannel, "CloseChannel", true},
	MsgTypeSetExtranoncePrefix:                  {MsgTypeSetExtranoncePrefix, "SetExtranoncePrefix", true},
	MsgTypeSubmitSharesStandard:                 {MsgTypeSubmitSharesStandard, "SubmitSharesStandard", true},
	MsgTypeSubmitSharesExtended:                 {MsgTypeSubmitSharesExtended, "SubmitSharesExtended", true},
	MsgTypeSubmitSharesSuccess:                  {MsgTypeSubmitSharesSuccess, "SubmitSharesSuccess", true},
	MsgTypeSubmitSharesError:                    {MsgTypeSubmitSharesError, "SubmitSharesError", true},
	MsgTypeNewMiningJob:                         {MsgTypeNewMiningJob, "NewMiningJob", true},
	MsgTypeNewExtendedMiningJob:                 {MsgTypeNewExtendedMiningJob, "NewExtendedMiningJob", true},
	MsgTypeSetNewPrevHash:                       {MsgTypeSetNewPrevHash, "SetNewPrevHash", true},
	MsgTypeSetTarget:                            {MsgTypeSetTarget, "SetTarget", true},
	MsgTypeSetCustomMiningJob:                   {MsgTypeSetCustomMiningJob, "SetCustomMiningJob", false},
	MsgTypeSetCustomMiningJobSuccess:            {MsgTypeSetCustomMiningJobSuccess, "SetCustomMiningJobSuccess", false},
	MsgTypeSetCustomMiningJobError:              {MsgTypeSetCustomMiningJobError, "SetCustomMiningJobError", false},
	MsgTypeReconnect:                            {MsgTypeReconnect, "Reconnect", false},
	MsgTypeSetGroupChannel:                      {MsgTypeSetGroupChannel, "SetGroupChannel", false},
	MsgTypeAllocateMiningJobToken:               {MsgTypeAllocateMiningJobToken, "AllocateMiningJobToken", false},
	MsgTypeAllocateMiningJobTokenSuccess:        {MsgTypeAllocateMiningJobTokenSuccess, "AllocateMiningJobTokenSuccess", false},
	MsgTypeAllocateMiningJobTokenError:          {MsgTypeAllocateMiningJobTokenError, "AllocateMiningJobTokenError", false},
	MsgTypeIdentifyTransactions:                 {MsgTypeIdentifyTransactions, "IdentifyTransactions", false},
	MsgTypeIdentifyTransactionsSuccess:          {MsgTypeIdentifyTransactionsSuccess, "IdentifyTransactionsSuccess", false},
	MsgTypeProvideMissingTransactions:           {MsgTypeProvideMissingTransactions, "ProvideMissingTransactions", false},
	MsgTypeProvideMissingTransactionsSuccess:    {MsgTypeProvideMissingTransactionsSuccess, "ProvideMissingTransactionsSuccess", false},
	MsgTypeCoinbaseOutputDataSize:               {MsgTypeCoinbaseOutputDataSize, "CoinbaseOutputDataSize", false},
	MsgTypeNewTemplate:                          {MsgTypeNewTemplate, "NewTemplate", false},
	MsgTypeSetNewPrevHashTDP:                    {MsgTypeSetNewPrevHashTDP, "SetNewPrevHashTDP", false},
	MsgTypeRequestTransactionData:               {MsgTypeRequestTransactionData, "RequestTransactionData", false},
	MsgTypeRequestTransactionDataSuccess:        {MsgTypeRequestTransactionDataSuccess, "RequestTransactionDataSuccess", false},
	MsgTypeRequestTransactionDataError:          {MsgTypeRequestTransactionDataError, "RequestTransactionDataError", false},
	MsgTypeSubmitSolution:                       {MsgTypeSubmitSolution, "SubmitSolution", false},
}

// Frame represents a Stratum V2 message frame
type Frame struct {
	ExtensionType uint16
	MessageType   uint8
	PayloadLength uint32
	Payload       []byte
}

// CreateFrame creates a message frame from message type and payload
func CreateFrame(extensionType uint16, msgType uint8, payload []byte) (*Frame, error) {
	info, ok := messageTypeMap[msgType]
	if !ok {
		return nil, fmt.Errorf("unknown message type: 0x%02x", msgType)
	}

	// Set channel message bit if needed
	ext := extensionType
	if info.IsChannelMsg {
		ext |= ChannelMessageBit
	}

	if len(payload) > (1<<24)-1 {
		return nil, errors.New("payload too large")
	}

	return &Frame{
		ExtensionType: ext,
		MessageType:   msgType,
		PayloadLength: uint32(len(payload)),
		Payload:       payload,
	}, nil
}

// ToBytes serializes the frame to bytes
func (f *Frame) ToBytes() ([]byte, error) {
	lenBytes, err := U24(f.PayloadLength)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, 6+len(f.Payload))
	result = append(result, U16(f.ExtensionType)...)
	result = append(result, U8(f.MessageType)...)
	result = append(result, lenBytes...)
	result = append(result, f.Payload...)
	return result, nil
}

// ParseFrame parses a frame from bytes
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < 6 {
		return nil, errors.New("insufficient data for frame header")
	}

	extType, err := ReadU16(data[0:2])
	if err != nil {
		return nil, err
	}

	msgType := data[2]

	payloadLen, err := ReadU24(data[3:6])
	if err != nil {
		return nil, err
	}

	if len(data) < 6+int(payloadLen) {
		return nil, fmt.Errorf("insufficient data for payload: expected %d, got %d", 6+payloadLen, len(data))
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[6:6+payloadLen])

	return &Frame{
		ExtensionType: extType,
		MessageType:   msgType,
		PayloadLength: payloadLen,
		Payload:       payload,
	}, nil
}

// GetMessageTypeName returns the name of a message type
func GetMessageTypeName(msgType uint8) string {
	if info, ok := messageTypeMap[msgType]; ok {
		return info.Name
	}
	return fmt.Sprintf("Unknown(0x%02x)", msgType)
}

// IsChannelMessage returns true if the message type is a channel message
func IsChannelMessage(msgType uint8) bool {
	if info, ok := messageTypeMap[msgType]; ok {
		return info.IsChannelMsg
	}
	return false
}
