package server_hello

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/piligrimm/tls/shared/spec"
	"github.com/piligrimm/tls/shared/utils"
)

func MarshalServerHello(serverHello *spec.ServerHello) []byte {
	payload := []byte{}
	payload = append(payload, serverHello.ServerVersion.Major, serverHello.ServerVersion.Minor)

	payload = append(payload, serverHello.Random...)

	payload = append(payload, byte(len(serverHello.SessionID)))
	payload = append(payload, serverHello.SessionID...)

	payload = append(payload, byte(serverHello.CipherSuite>>8), byte(serverHello.CipherSuite))

	payload = append(payload, byte(serverHello.CompressionMethod))

	ownExtensionsLength := utils.RawExtensionsLen(serverHello.Extensions)
	if ownExtensionsLength == 0 {
		return payload
	}

	rawExtensionsLength := make([]byte, 2)
	binary.BigEndian.PutUint16(rawExtensionsLength, uint16(ownExtensionsLength))
	payload = append(payload, rawExtensionsLength...)
	for _, extension := range serverHello.Extensions {
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

func UnmarshalServerHello(serverHelloRaw []byte) (*spec.ServerHello, error) {
	off := 0
	need := func(n int) error {
		if off+n > len(serverHelloRaw) {
			return fmt.Errorf("truncated ServerHello at offset %d, need %d bytes", off, n)
		}
		return nil
	}

	if err := need(2); err != nil {
		return nil, err
	}
	protocolVersion, err := utils.ParseProtocolVersionFromRawPayload(serverHelloRaw[off : off+2])
	if err != nil {
		return nil, err
	}
	off += 2

	if err := need(32); err != nil {
		return nil, err
	}
	random := append([]byte(nil), serverHelloRaw[off:off+32]...)
	off += 32

	if err := need(1); err != nil {
		return nil, err
	}
	sessionIdLength := int(serverHelloRaw[off])

	if sessionIdLength > 32 {
		return nil, errors.New("session ID cannot be longer than 32 bytes")
	}
	off += 1

	if err := need(sessionIdLength); err != nil {
		return nil, err
	}

	sessionId := append([]byte(nil), serverHelloRaw[off:off+sessionIdLength]...)
	off += sessionIdLength

	if err := need(2); err != nil {
		return nil, err
	}
	cipherSuite := spec.CipherSuite(binary.BigEndian.Uint16(serverHelloRaw[off : off+2]))
	off += 2

	if err := need(1); err != nil {
		return nil, err
	}
	compressionMethod := spec.CompressionMethod(serverHelloRaw[off])
	off += 1

	extensions := []spec.Extension(nil)

	if off < len(serverHelloRaw) {
		if err := need(2); err != nil {
			return nil, err
		}
		extensionsLength := binary.BigEndian.Uint16(serverHelloRaw[off : off+2])
		off += 2
		endExt := off + int(extensionsLength)
		for off < endExt {
			if err := need(2); err != nil {
				return nil, err
			}
			extTypeRaw := serverHelloRaw[off : off+2]
			extType := spec.ExtensionType(binary.BigEndian.Uint16(extTypeRaw))
			off += 2

			if err := need(2); err != nil {
				return nil, err
			}
			opaqueLength := int(binary.BigEndian.Uint16(serverHelloRaw[off : off+2]))
			off += 2

			if err := need(opaqueLength); err != nil {
				return nil, err
			}
			opaque := append([]byte(nil), serverHelloRaw[off:off+opaqueLength]...)
			off += opaqueLength

			extensions = append(extensions, spec.Extension{Type: extType, Opaque: opaque})
		}
	}

	return &spec.ServerHello{
		ServerVersion:     *protocolVersion,
		Random:            random,
		SessionID:         sessionId,
		CipherSuite:       cipherSuite,
		CompressionMethod: compressionMethod,
		Extensions:        extensions,
	}, nil
}
