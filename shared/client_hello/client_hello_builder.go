package client_hello

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/piligrimm/tls/shared/spec"
)

func NewClientHello(
	random []byte,
	sessionId []byte,
	cipherSuites []spec.CipherSuite,
	extensions []spec.Extension,
) (*spec.ClientHello, error) {
	if len(random) != 32 {
		return nil, errors.New("random must contain 32 bytes")
	}

	if len(sessionId) > 32 {
		return nil, errors.New("session ID cannot be longer than 32 bytes")
	}

	if 2*len(cipherSuites) > math.MaxUint16 {
		return nil, fmt.Errorf("raw cipher suites cannot exceed %v bytes", math.MaxUint16)
	}

	if len(cipherSuites) == 0 {
		return nil, errors.New("at least one cipher suite is required")
	}
	seenCipherSuites := make(map[spec.CipherSuite]bool)
	supportedCipherSuites := spec.SupportedCipherSuites()
	for _, cipherSuite := range cipherSuites {
		if !slices.Contains(supportedCipherSuites, cipherSuite) {
			return nil, fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
		}

		if seenCipherSuites[cipherSuite] {
			return nil, fmt.Errorf("duplicate cipher suite: %v", cipherSuite)
		}
		seenCipherSuites[cipherSuite] = true
	}

	extensionsSum := 0
	for _, extension := range extensions {
		extensionsSum += extensionLen(extension)
	}
	if extensionsSum > math.MaxUint16 {
		return nil, fmt.Errorf("raw extensions cannot exceed %v bytes", math.MaxUint16)
	}
	seenExtensionTypes := make(map[spec.ExtensionType]bool)
	possibleExtensions := spec.ExtensionTypes()
	for _, extension := range extensions {
		if !slices.Contains(possibleExtensions, extension.Type) {
			return nil, fmt.Errorf("unsupported extension %v", extension.Type)
		}

		if len(extension.Opaque) > math.MaxUint16 {
			return nil, fmt.Errorf("extension %v exceeds max opaque length", extension.Type)
		}

		if seenExtensionTypes[extension.Type] {
			return nil, fmt.Errorf("duplicate extension: %v", extension.Type)
		}
		seenExtensionTypes[extension.Type] = true
	}

	const compressionNull = 0
	compression := []byte{compressionNull}

	return &spec.ClientHello{
		ClientVersion: spec.Tls12ProtocolVersion(),
		Random:        copySlice(random),
		SessionID:     copySlice(sessionId),
		CipherSuites:  copySlice(cipherSuites),
		Compression:   compression,
		Extensions:    copyExtensions(extensions),
	}, nil
}

func extensionLen(extension spec.Extension) int {
	return 2 + 2 + len(extension.Opaque)
}

func extensionsLen(extensions []spec.Extension) int {
	extensionsSum := 0
	for _, extension := range extensions {
		extensionsSum += extensionLen(extension)
	}

	return extensionsSum
}

func copySlice[T ~byte | spec.CipherSuite](src []T) []T {
	dst := make([]T, len(src))
	copy(dst, src)
	return dst
}

func copyExtensions(src []spec.Extension) []spec.Extension {
	dst := make([]spec.Extension, len(src))
	for i, extSrc := range src {
		opaque := copySlice(extSrc.Opaque)
		dst[i] = spec.Extension{
			Type:   extSrc.Type,
			Opaque: opaque,
		}
	}

	slices.SortFunc(dst, func(a, b spec.Extension) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		default:
			return 0
		}
	})
	return dst
}

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
