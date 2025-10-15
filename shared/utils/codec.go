package utils

import (
	"encoding/binary"
	"fmt"
	"math"
)

// todo: external user should not bother him/herself of creating opaque vector => add types
func NewOpaqueVector16(values []byte) ([]byte, error) {
	return newLengthPrefixedOpaque(values, math.MaxUint16, 2, func(length []byte, size int) {
		binary.BigEndian.PutUint16(length, uint16(size))
	}, "opaque vector with uint16 length prefix")
}

func NewOpaqueVector8(values []byte) ([]byte, error) {
	return newLengthPrefixedOpaque(values, math.MaxUint8, 1, func(length []byte, size int) {
		length[0] = byte(size)
	}, "opaque vector with uint8 length prefix")
}

func newLengthPrefixedOpaque(values []byte, maxLen int, prefixSize int, writeLength func([]byte, int), description string) ([]byte, error) {
	if len(values) > maxLen {
		return nil, fmt.Errorf("%s cannot be longer than %d", description, maxLen)
	}

	if len(values) == 0 {
		return []byte(nil), nil
	}

	length := make([]byte, prefixSize)
	writeLength(length, len(values))
	return append(length, values...), nil
}
