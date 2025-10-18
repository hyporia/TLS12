package utils

import (
	"encoding/binary"
	"fmt"
	"math"
)

// todo: external user should not bother him/herself of creating opaque vector => add types
func NewOpaqueVector16(values []byte) ([]byte, error) {
	if len(values) > math.MaxUint16 {
		return nil, fmt.Errorf("%s cannot be longer than %d", "opaque vector with uint16 length prefix", math.MaxUint16)
	}
	if len(values) == 0 {
		return []byte(nil), nil
	}
	length := binary.BigEndian.AppendUint16([]byte(nil), CastUint16OrPanic(len(values)))
	return append(length, values...), nil
}

func NewOpaqueVector8(values []byte) ([]byte, error) {
	if len(values) > math.MaxUint8 {
		return nil, fmt.Errorf("%s cannot be longer than %d", "opaque vector with uint8 length prefix", math.MaxUint8)
	}
	if len(values) == 0 {
		return []byte(nil), nil
	}

	return append([]byte{byte(CastUint8OrPanic(len(values)))}, values...), nil
}
