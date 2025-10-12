package shared

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/piligrimm/tls/shared/spec"
)

type Extension struct {
	Type   spec.ExtensionType
	Opaque []byte
}

type ProtocolVersion struct {
	major uint8 // 0x03 for TLS 1.x
	minor uint8 // 0x03 for TLS 1.2
}

type ClientHello struct {
	clientVersion ProtocolVersion

	random []byte

	sessionId []byte

	cipherSuites []spec.CipherSuite

	compression []byte

	extensions []Extension
}

func NewClientHello(
	random []byte,
	sessionId []byte,
	cipherSuites []spec.CipherSuite,
	extensions []Extension,
) (*ClientHello, error) {
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

	return &ClientHello{
		clientVersion: Tls12ProtocolVersion(),
		random:        copySlice(random),
		sessionId:     copySlice(sessionId),
		cipherSuites:  copySlice(cipherSuites),
		compression:   compression,
		extensions:    copyExtensions(extensions), // todo: sort extensions
	}, nil
}

func MarshalClientHello(clientHello *ClientHello) []byte {
	payload := []byte{}
	payload = append(payload, clientHello.clientVersion.major, clientHello.clientVersion.minor)

	payload = append(payload, clientHello.random...)

	payload = append(payload, byte(len(clientHello.sessionId)))
	payload = append(payload, clientHello.sessionId...)

	rawCipherSuiteLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawCipherSuiteLength, uint16(2*len(clientHello.cipherSuites)))
	payload = append(payload, rawCipherSuiteLength...)
	for _, cipherSuite := range clientHello.cipherSuites {
		payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))
	}

	payload = append(payload, byte(len(clientHello.compression)))
	payload = append(payload, clientHello.compression...)

	ownExtensionsLength := extensionsLen(clientHello.extensions)
	if ownExtensionsLength == 0 {
		return payload
	}

	rawExtensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawExtensionsLength, uint16(ownExtensionsLength))
	payload = append(payload, rawExtensionsLength...)
	for _, extension := range clientHello.extensions {
		rawExtensionType := make([]byte, 2)
		binary.BigEndian.PutUint16(rawExtensionType, uint16(extension.Type))
		payload = append(payload, rawExtensionType...)

		rawOpaqueLength := make([]byte, 2)
		binary.BigEndian.PutUint16(rawOpaqueLength, uint16(len(extension.Opaque)))
		payload = append(payload, rawOpaqueLength...)

		payload = append(payload, extension.Opaque...)
	}

	return payload
}

func UnmarshalClientHello(raw []byte) (*ClientHello, error) {
	const minLen = 41
	if len(raw) < minLen {
		return nil, fmt.Errorf("raw payload too short to be a valid ClientHello")
	}

	off := 0
	need := func(n int) error {
		if len(raw)-off < n {
			return fmt.Errorf("truncated ClientHello at offset %d, need %d bytes", off, n)
		}
		return nil
	}

	// protocol version (2)
	if err := need(2); err != nil {
		return nil, err
	}
	protocolVersion, err := parseProtocolVersionFromRawPayload(raw[off : off+2])
	if err != nil {
		return nil, err
	}
	off += 2

	// random (32)
	if err := need(32); err != nil {
		return nil, err
	}
	random := append([]byte(nil), raw[off:off+32]...)
	off += 32

	// session_id
	if err := need(1); err != nil {
		return nil, err
	}
	sidLen := int(raw[off])
	off++
	if sidLen > 32 {
		return nil, fmt.Errorf("session ID length %d exceeds 32", sidLen)
	}
	if err := need(sidLen); err != nil {
		return nil, err
	}
	sessionId := append([]byte(nil), raw[off:off+sidLen]...)
	off += sidLen

	// cipher_suites
	if err := need(2); err != nil {
		return nil, err
	}
	csLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
	off += 2
	if csLen == 0 || csLen%2 != 0 {
		return nil, fmt.Errorf("incorrect cipher_suites length %d", csLen)
	}
	if err := need(csLen); err != nil {
		return nil, err
	}
	numSuites := csLen / 2
	cipherSuites := make([]spec.CipherSuite, numSuites)
	for i := 0; i < numSuites; i++ {
		cipherSuites[i] = spec.CipherSuite(binary.BigEndian.Uint16(raw[off+2*i : off+2*i+2]))
	}
	off += csLen

	// compression_methods
	if err := need(1); err != nil {
		return nil, err
	}
	compLen := int(raw[off])
	off++
	if compLen == 0 {
		return nil, fmt.Errorf("compression methods length must be >= 1")
	}
	if err := need(compLen); err != nil {
		return nil, err
	}
	compression := append([]byte(nil), raw[off:off+compLen]...)
	off += compLen
	// null(0) compression method is required in TLS 1.2
	hasNull := false
	for _, m := range compression {
		if m == 0 {
			hasNull = true
			break
		}
	}
	if !hasNull {
		return nil, fmt.Errorf("null compression method (0) is required")
	}

	// extensions (optional)
	extensions := make([]Extension, 0)
	if off < len(raw) {
		if err := need(2); err != nil {
			return nil, err
		}
		extLen := int(binary.BigEndian.Uint16(raw[off : off+2]))
		off += 2
		if err := need(extLen); err != nil {
			return nil, err
		}
		endExt := off + extLen

		for off < endExt {
			// header: type(2) + length(2)
			if endExt-off < 4 {
				return nil, fmt.Errorf("truncated extension header at offset %d", off)
			}
			extType := spec.ExtensionType(binary.BigEndian.Uint16(raw[off : off+2]))
			opaqueLen := int(binary.BigEndian.Uint16(raw[off+2 : off+4]))
			off += 4
			if endExt-off < opaqueLen {
				return nil, fmt.Errorf("truncated extension body at offset %d", off)
			}
			opaque := append([]byte(nil), raw[off:off+opaqueLen]...)
			off += opaqueLen

			extensions = append(extensions, Extension{Type: extType, Opaque: opaque})
		}
	}

	return &ClientHello{
		clientVersion: *protocolVersion,
		random:        random,
		sessionId:     sessionId,
		cipherSuites:  cipherSuites,
		compression:   compression,
		extensions:    extensions,
	}, nil
}

func extensionLen(extension Extension) int {
	return 2 + 2 + len(extension.Opaque)
}

func extensionsLen(extensions []Extension) int {
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

func copyExtensions(src []Extension) []Extension {
	dst := make([]Extension, len(src))
	for i, extSrc := range src {
		opaque := copySlice(extSrc.Opaque)
		dst[i] = Extension{
			Type:   extSrc.Type,
			Opaque: opaque,
		}
	}

	slices.SortFunc(dst, func(a, b Extension) int {
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

func NewTwoBytesLengthOpaque(values []byte) ([]byte, error) {
	if len(values) > math.MaxUint16 {
		return nil, fmt.Errorf("opaque with two bytes for length cannot be longer than %v", len(values))
	}

	if len(values) == 0 {
		return []byte(nil), nil
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(values)))
	return append(length, values...), nil
}

func NewOneByteLengthOpaque(values []byte) ([]byte, error) {
	if len(values) > math.MaxUint8 {
		return nil, fmt.Errorf("opaque with one byte for length cannot be longer than %v", len(values))
	}

	if len(values) == 0 {
		return []byte(nil), nil
	}

	length := []byte{byte(len(values))}
	return append(length, values...), nil
}
