package utils

import (
	"fmt"
	"math"
)

func CastUint16OrPanic(value int) uint16 {
	if value < 0 || value > math.MaxUint16 {
		panic(fmt.Sprintf("cannot cast %d to uint16", value))
	}

	return uint16(value)
}

func CastUint8OrPanic(value int) uint8 {
	if value < 0 || value > math.MaxUint8 {
		panic(fmt.Sprintf("cannot cast %d to uint8", value))
	}

	return uint8(value)
}
