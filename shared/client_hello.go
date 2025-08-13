package shared

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
)

type ClientHello struct {
	clientVersion ProtocolVersion

	random []byte

	sessionId []byte

	cipherSuites []CipherSuite

	compression []byte

	extensions []Extension
}

func NewClientHello(
	_random []byte,
	_sessionId []byte,
	_cipherSuites []CipherSuite,
	_extensions []Extension,
) (*ClientHello, error) {
	if len(_random) != 32 {
		return nil, errors.New("random must contain 32 bytes")
	}

	if len(_sessionId) > 32 {
		return nil, errors.New("session ID cannot be longer than 32 bytes")
	}

	if 2*len(_cipherSuites) > math.MaxUint16 {
		return nil, fmt.Errorf("raw cipher suites cannot exceed %v bytes", math.MaxUint16)
	}

	if len(_cipherSuites) == 0 {
		return nil, errors.New("at least one cipher suite is required")
	}
	seenCipherSuites := make(map[CipherSuite]bool)
	supportedCipherSuites := SupportedCipherSuites()
	for _, cipherSuite := range _cipherSuites {
		if !slices.Contains(supportedCipherSuites, cipherSuite) {
			return nil, fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
		}

		if seenCipherSuites[cipherSuite] {
			return nil, fmt.Errorf("duplicate cipher suite: %v", cipherSuite)
		}
		seenCipherSuites[cipherSuite] = true
	}

	extensionsSum := 0
	for _, extension := range _extensions {
		extensionsSum += extensionLen(extension)
	}
	if extensionsSum > math.MaxUint16 {
		return nil, fmt.Errorf("raw extensions cannot exceed %v bytes", math.MaxUint16)
	}
	seenExtensionTypes := make(map[ExtensionType]bool)
	possibleExtensions := ExtensionTypes()
	for _, extension := range _extensions {
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

	return &ClientHello{
		clientVersion: Tls12ProtocolVersion(),
		random:        copyInternal(_random),
		sessionId:     copyInternal(_sessionId),
		cipherSuites:  copyInternal(_cipherSuites),
		compression:   compression,
		extensions:    copyExtensions(_extensions),
	}, nil
}

func RawPayloadLength(clientHello *ClientHello) int {
	version := 2
	random := 32
	sessionId := 1 + len(clientHello.sessionId)
	cipherSuites := 2 + 2*len(clientHello.cipherSuites)
	compression := 1 + 1 // 1 length + 1 byte for compression method

	extensionsLen := extensionsLen(clientHello.extensions)
	extensions := 0
	if extensionsLen > 0 {
		extensions = 2 + extensionsLen
	}

	return version + random + sessionId + cipherSuites + compression + extensions
}

func RawPayload(clientHello *ClientHello) []byte {
	payload := []byte{}
	payload = append(payload, clientHello.clientVersion.major, clientHello.clientVersion.minor)

	payload = append(payload, clientHello.random[:]...)

	payload = append(payload, byte(len(clientHello.sessionId)))
	payload = append(payload, clientHello.sessionId[:]...)

	rawCipherSuiteLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawCipherSuiteLength, uint16(2*len(clientHello.cipherSuites)))
	payload = append(payload, rawCipherSuiteLength[:]...)
	for _, cipherSuite := range clientHello.cipherSuites {
		payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))
	}

	payload = append(payload, byte(len(clientHello.compression)))
	payload = append(payload, clientHello.compression[:]...)

	ownExtensionsLength := extensionsLen(clientHello.extensions)
	if ownExtensionsLength == 0 {
		return payload
	}

	rawExtensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawExtensionsLength, uint16(ownExtensionsLength))
	payload = append(payload, rawExtensionsLength[:]...)
	for _, extension := range clientHello.extensions {
		rawExtensionType := make([]byte, 2)
		binary.BigEndian.PutUint16(rawExtensionType, uint16(extension.Type))
		payload = append(payload, rawExtensionType[:]...)

		rawOpaqueLength := make([]byte, 2)
		binary.BigEndian.PutUint16(rawOpaqueLength, uint16(len(extension.Opaque)))
		payload = append(payload, rawOpaqueLength[:]...)

		payload = append(payload, extension.Opaque[:]...)
	}

	return payload
}

func extensionLen(extension Extension) int {
	return 2 + 2 + len(extension.Opaque) // 2 bytes for type, 2 bytes for length of opaque data, and len for opaque data
}

func extensionsLen(extensions []Extension) int {
	extensionsSum := 0
	for _, extension := range extensions {
		extensionsSum += extensionLen(extension)
	}

	return extensionsSum
}

func copyInternal[T byte | CipherSuite](src []T) []T {
	dst := make([]T, len(src))
	copy(dst, src)
	return dst
}

func copyExtensions(src []Extension) []Extension {
	dst := make([]Extension, len(src))
	for i, extSrc := range src {
		opaque := copyInternal(extSrc.Opaque)
		dst[i] = Extension{
			Type:   extSrc.Type,
			Opaque: opaque,
		}
	}
	return dst
}
