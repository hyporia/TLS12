package shared

import "fmt"

type ECPointFormat uint8

const (
	ECPointFormatUncompressed            ECPointFormat = 0x00
	ECPointFormatAnsiX962CompressedPrime ECPointFormat = 0x01
	ECPointFormatAnsiX962CompressedChar2 ECPointFormat = 0x02
)

func (p ECPointFormat) String() string {
	switch p {
	case ECPointFormatUncompressed:
		return "Uncompressed"
	case ECPointFormatAnsiX962CompressedPrime:
		return "ANSI X962 Compressed Prime"
	case ECPointFormatAnsiX962CompressedChar2:
		return "ANSI X962 Compressed Char2"
	default:
		return fmt.Sprintf("ECPointFormat(0x%02x)", uint8(p))
	}
}
