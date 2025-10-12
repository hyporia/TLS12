package client_hello

import (
	"encoding/binary"
	"fmt"

	"github.com/piligrimm/tls/shared/spec"
)

func MarshalClientHello(clientHello *spec.ClientHello) []byte {
	payload := []byte{}
	payload = append(payload, clientHello.ClientVersion.Major, clientHello.ClientVersion.Minor)

	payload = append(payload, clientHello.Random...)

	payload = append(payload, byte(len(clientHello.SessionID)))
	payload = append(payload, clientHello.SessionID...)

	rawCipherSuiteLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawCipherSuiteLength, uint16(2*len(clientHello.CipherSuites)))
	payload = append(payload, rawCipherSuiteLength...)
	for _, cipherSuite := range clientHello.CipherSuites {
		payload = append(payload, byte(cipherSuite>>8), byte(cipherSuite))
	}

	payload = append(payload, byte(len(clientHello.Compression)))
	payload = append(payload, clientHello.Compression...)

	ownExtensionsLength := extensionsLen(clientHello.Extensions)
	if ownExtensionsLength == 0 {
		return payload
	}

	rawExtensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawExtensionsLength, uint16(ownExtensionsLength))
	payload = append(payload, rawExtensionsLength...)
	for _, extension := range clientHello.Extensions {
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

func UnmarshalClientHello(raw []byte) (*spec.ClientHello, error) {
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
	extensions := make([]spec.Extension, 0)
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

			extensions = append(extensions, spec.Extension{Type: extType, Opaque: opaque})
		}
	}

	return &spec.ClientHello{
		ClientVersion: *protocolVersion,
		Random:        random,
		SessionID:     sessionId,
		CipherSuites:  cipherSuites,
		Compression:   compression,
		Extensions:    extensions,
	}, nil
}

func parseProtocolVersionFromRawPayload(rawPayload []byte) (*spec.ProtocolVersion, error) {
	if len(rawPayload) != 2 {
		return nil, fmt.Errorf("protocol payload has incorrect length")
	}

	tls12ProtocolVersion := spec.Tls12ProtocolVersion()

	if rawPayload[0] != tls12ProtocolVersion.Major || rawPayload[1] != tls12ProtocolVersion.Minor {
		return nil, fmt.Errorf("incorrect protocol version")
	}

	return &tls12ProtocolVersion, nil
}
