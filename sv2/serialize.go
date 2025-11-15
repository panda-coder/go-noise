package sv2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Serialization helper functions for Stratum V2 data types

// U8 encodes an 8-bit unsigned integer (1 byte, little-endian)
func U8(v uint8) []byte {
	return []byte{v}
}

// U16 encodes a 16-bit unsigned integer (2 bytes, little-endian)
func U16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// U24 encodes a 24-bit unsigned integer (3 bytes, little-endian)
func U24(v uint32) ([]byte, error) {
	if v >= 1<<24 {
		return nil, errors.New("U24: value overflow")
	}
	b := make([]byte, 3)
	binary.LittleEndian.PutUint32(b[:4], v)
	return b[:3], nil
}

// U32 encodes a 32-bit unsigned integer (4 bytes, little-endian)
func U32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// U64 encodes a 64-bit unsigned integer (8 bytes, little-endian)
func U64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// F32 encodes a 32-bit floating-point number (4 bytes, little-endian)
func F32(v float32) []byte {
	bits := math.Float32bits(v)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, bits)
	return b
}

// U256 encodes a 256-bit unsigned integer (32 bytes, little-endian)
func U256(v []byte) ([]byte, error) {
	if len(v) != 32 {
		return nil, fmt.Errorf("U256: expected 32 bytes, got %d", len(v))
	}
	return v, nil
}

// BOOL encodes a boolean value (1 byte)
func BOOL(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}

// STR0_255 encodes a string with length prefix (0-255 bytes)
// Format: [1-byte length][string bytes]
func STR0_255(s string) ([]byte, error) {
	if len(s) > 255 {
		return nil, errors.New("STR0_255: string too long")
	}
	b := make([]byte, 1+len(s))
	b[0] = byte(len(s))
	copy(b[1:], s)
	return b, nil
}

// B0_32 encodes bytes with length prefix (0-32 bytes)
// Format: [1-byte length][bytes]
func B0_32(data []byte) ([]byte, error) {
	if len(data) > 32 {
		return nil, errors.New("B0_32: data too long")
	}
	b := make([]byte, 1+len(data))
	b[0] = byte(len(data))
	copy(b[1:], data)
	return b, nil
}

// B0_255 encodes bytes with length prefix (0-255 bytes)
// Format: [1-byte length][bytes]
func B0_255(data []byte) ([]byte, error) {
	if len(data) > 255 {
		return nil, errors.New("B0_255: data too long")
	}
	b := make([]byte, 1+len(data))
	b[0] = byte(len(data))
	copy(b[1:], data)
	return b, nil
}

// B0_64K encodes bytes with 16-bit length prefix (0-64K bytes)
// Format: [2-byte length][bytes]
func B0_64K(data []byte) ([]byte, error) {
	if len(data) > 65535 {
		return nil, errors.New("B0_64K: data too long")
	}
	b := make([]byte, 2+len(data))
	binary.LittleEndian.PutUint16(b, uint16(len(data)))
	copy(b[2:], data)
	return b, nil
}

// B0_16M encodes bytes with 24-bit length prefix (0-16M bytes)
// Format: [3-byte length][bytes]
func B0_16M(data []byte) ([]byte, error) {
	if len(data) > (1<<24)-1 {
		return nil, errors.New("B0_16M: data too long")
	}
	b := make([]byte, 3+len(data))
	binary.LittleEndian.PutUint32(b[:4], uint32(len(data)))
	copy(b[3:], data)
	return b[0:3+len(data)], nil
}

// Deserialization functions

// ReadU8 reads a uint8 from bytes
func ReadU8(data []byte) (uint8, error) {
	if len(data) < 1 {
		return 0, errors.New("ReadU8: insufficient data")
	}
	return data[0], nil
}

// ReadU16 reads a uint16 from bytes (little-endian)
func ReadU16(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, errors.New("ReadU16: insufficient data")
	}
	return binary.LittleEndian.Uint16(data), nil
}

// ReadU24 reads a uint32 from 3 bytes (little-endian)
func ReadU24(data []byte) (uint32, error) {
	if len(data) < 3 {
		return 0, errors.New("ReadU24: insufficient data")
	}
	b := make([]byte, 4)
	copy(b, data[:3])
	return binary.LittleEndian.Uint32(b), nil
}

// ReadU32 reads a uint32 from bytes (little-endian)
func ReadU32(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, errors.New("ReadU32: insufficient data")
	}
	return binary.LittleEndian.Uint32(data), nil
}

// ReadU64 reads a uint64 from bytes (little-endian)
func ReadU64(data []byte) (uint64, error) {
	if len(data) < 8 {
		return 0, errors.New("ReadU64: insufficient data")
	}
	return binary.LittleEndian.Uint64(data), nil
}

// ReadU256 reads 32 bytes as U256
func ReadU256(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, errors.New("ReadU256: insufficient data")
	}
	result := make([]byte, 32)
	copy(result, data[:32])
	return result, nil
}

// ReadBOOL reads a boolean from bytes
func ReadBOOL(data []byte) (bool, error) {
	if len(data) < 1 {
		return false, errors.New("ReadBOOL: insufficient data")
	}
	return data[0] != 0, nil
}

// ReadSTR0_255 reads a length-prefixed string (0-255 bytes)
func ReadSTR0_255(data []byte) (string, int, error) {
	if len(data) < 1 {
		return "", 0, errors.New("ReadSTR0_255: insufficient data")
	}
	length := int(data[0])
	if len(data) < 1+length {
		return "", 0, errors.New("ReadSTR0_255: insufficient data for string")
	}
	return string(data[1 : 1+length]), 1 + length, nil
}

// ReadB0_32 reads length-prefixed bytes (0-32 bytes)
func ReadB0_32(data []byte) ([]byte, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("ReadB0_32: insufficient data")
	}
	length := int(data[0])
	if length > 32 {
		return nil, 0, errors.New("ReadB0_32: length exceeds 32")
	}
	if len(data) < 1+length {
		return nil, 0, errors.New("ReadB0_32: insufficient data for bytes")
	}
	result := make([]byte, length)
	copy(result, data[1:1+length])
	return result, 1 + length, nil
}

// ReadB0_255 reads length-prefixed bytes (0-255 bytes)
func ReadB0_255(data []byte) ([]byte, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("ReadB0_255: insufficient data")
	}
	length := int(data[0])
	if len(data) < 1+length {
		return nil, 0, errors.New("ReadB0_255: insufficient data for bytes")
	}
	result := make([]byte, length)
	copy(result, data[1:1+length])
	return result, 1 + length, nil
}

// ReadB0_64K reads length-prefixed bytes (0-64K bytes)
func ReadB0_64K(data []byte) ([]byte, int, error) {
	if len(data) < 2 {
		return nil, 0, errors.New("ReadB0_64K: insufficient data")
	}
	length := int(binary.LittleEndian.Uint16(data))
	if len(data) < 2+length {
		return nil, 0, errors.New("ReadB0_64K: insufficient data for bytes")
	}
	result := make([]byte, length)
	copy(result, data[2:2+length])
	return result, 2 + length, nil
}
