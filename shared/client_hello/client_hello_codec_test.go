package client_hello

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/piligrimm/tls/shared/spec"
)

func TestUnmarshalClientHello_ValidInput(t *testing.T) {
	rawPayload := []byte{
		0x03, 0x03, 0x6f, 0x98, 0x03, 0x8c, 0x08, 0x3e, 0xa1, 0x51, 0x38, 0x1e,
		0x0f, 0x4b, 0xec, 0xb7, 0x45, 0x0c, 0x52, 0xf5, 0x03, 0x7a, 0x33, 0x39,
		0xd9, 0x67, 0xf9, 0x5c, 0x38, 0xba, 0x2a, 0x6a, 0x31, 0x16, 0x00, 0x00,
		0x5c, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x30, 0xc0, 0x2c, 0xc0,
		0x28, 0xc0, 0x24, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9f, 0x00, 0x6b, 0x00,
		0x39, 0xff, 0x85, 0x00, 0xc4, 0x00, 0x88, 0x00, 0x81, 0x00, 0x9d, 0x00,
		0x3d, 0x00, 0x35, 0x00, 0xc0, 0x00, 0x84, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0,
		0x27, 0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09, 0x00, 0x9e, 0x00, 0x67, 0x00,
		0x33, 0x00, 0xbe, 0x00, 0x45, 0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00,
		0xba, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0x00, 0x05, 0x00, 0x04, 0xc0,
		0x12, 0xc0, 0x08, 0x00, 0x16, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x00, 0x00,
		0x34, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00,
		0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00, 0x23, 0x00,
		0x00, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x08, 0x06, 0x06, 0x01, 0x06,
		0x03, 0x08, 0x05, 0x05, 0x01, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x04,
		0x03, 0x02, 0x01, 0x02, 0x03,
	}

	clientHello, err := UnmarshalClientHello(rawPayload)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	tls12ProtocolVersion := spec.Tls12ProtocolVersion()
	if clientHello.ClientVersion.Major != tls12ProtocolVersion.Major || clientHello.ClientVersion.Minor != tls12ProtocolVersion.Minor {
		t.Errorf("Expected TLS 1.2 version(3, 3), got %d.%d", clientHello.ClientVersion.Major, clientHello.ClientVersion.Minor)
	}

	expectedRandom := []byte{
		0x6f, 0x98, 0x03, 0x8c, 0x08, 0x3e, 0xa1, 0x51,
		0x38, 0x1e, 0x0f, 0x4b, 0xec, 0xb7, 0x45, 0x0c,
		0x52, 0xf5, 0x03, 0x7a, 0x33, 0x39, 0xd9, 0x67,
		0xf9, 0x5c, 0x38, 0xba, 0x2a, 0x6a, 0x31, 0x16,
	}
	if !bytes.Equal(clientHello.Random, expectedRandom) {
		t.Errorf("Unexpected random: %x", clientHello.Random)
	}

	if len(clientHello.SessionID) != 0 {
		t.Errorf("Expected empty session ID, got %x", clientHello.SessionID)
	}

	expectedCipherSuites := []spec.CipherSuite{
		spec.CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		spec.CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		spec.CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		spec.CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		spec.CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		spec.CipherSuiteDHE_RSA_WITH_AES_256_GCM_SHA384,
		spec.CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA,
		spec.CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT,
		spec.CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		spec.CipherSuiteGOSTR341001_WITH_28147_CNT_IMIT,
		spec.CipherSuiteRSA_WITH_AES_256_GCM_SHA384,
		spec.CipherSuiteRSA_WITH_AES_256_CBC_SHA256,
		spec.CipherSuiteRSA_WITH_AES_256_CBC_SHA,
		spec.CipherSuiteRSA_WITH_CAMELLIA_256_CBC_SHA256,
		spec.CipherSuiteDH_anon_WITH_CAMELLIA_128_GCM_SHA256,
		spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		spec.CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		spec.CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA,
		spec.CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		spec.CipherSuiteDHE_RSA_WITH_AES_128_GCM_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA,
		spec.CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		spec.CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		spec.CipherSuiteRSA_WITH_AES_128_GCM_SHA256,
		spec.CipherSuiteRSA_WITH_AES_128_CBC_SHA256,
		spec.CipherSuiteRSA_WITH_AES_128_CBC_SHA,
		spec.CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA256,
		spec.CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA,
		spec.CipherSuiteECDHE_RSA_WITH_RC4_128_SHA,
		spec.CipherSuiteECDHE_ECDSA_WITH_RC4_128_SHA,
		spec.CipherSuiteRSA_WITH_RC4_128_SHA,
		spec.CipherSuiteRSA_WITH_RC4_128_MD5,
		spec.CipherSuiteECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		spec.CipherSuiteECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		spec.CipherSuiteDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		spec.CipherSuiteRSA_WITH_3DES_EDE_CBC_SHA,
		spec.CipherSuiteEMPTY_RENEGOTIATION_INFO_SCSV,
	}

	if len(clientHello.CipherSuites) != len(expectedCipherSuites) {
		t.Fatalf("Expected %d cipher suites, got %d", len(expectedCipherSuites), len(clientHello.CipherSuites))
	}

	for i, suite := range expectedCipherSuites {
		if clientHello.CipherSuites[i] != suite {
			t.Fatalf("Cipher suite mismatch at position %d: expected %v, got %v", i, suite, clientHello.CipherSuites[i])
		}
	}

	if len(clientHello.Compression) != 1 || clientHello.Compression[0] != 0x00 {
		t.Errorf("Expected only null compression, got %x", clientHello.Compression)
	}

	pointFormatsValues := []byte{byte(spec.ECPointFormatUncompressed)}
	pointFormats, _ := NewOpaqueVector8(pointFormatsValues)

	supportedGroups := []byte{0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}
	signatureAlgorithms := []byte{0x00, 0x16, 0x08, 0x06, 0x06, 0x01, 0x06, 0x03, 0x08, 0x05, 0x05, 0x01, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03}

	expectedExtensions := []spec.Extension{
		{Type: spec.ExtensionTypeECPointFormats, Opaque: pointFormats},
		{Type: spec.ExtensionTypeSupportedGroups, Opaque: supportedGroups},
		{Type: spec.ExtensionTypeSessionTicket, Opaque: nil},
		{Type: spec.ExtensionTypeSignatureAlgorithms, Opaque: signatureAlgorithms},
	}

	if len(clientHello.Extensions) != len(expectedExtensions) {
		t.Fatalf("Expected %d extensions, got %d", len(expectedExtensions), len(clientHello.Extensions))
	}

	for i, ext := range expectedExtensions {
		got := clientHello.Extensions[i]
		if got.Type != ext.Type {
			t.Fatalf("Extension type mismatch at index %d: expected %v, got %v", i, ext.Type, got.Type)
		}
		if !bytes.Equal(got.Opaque, ext.Opaque) {
			t.Fatalf("Extension opaque mismatch at index %d: expected %x, got %x", i, ext.Opaque, got.Opaque)
		}
	}
}

func TestMarshalClientHello_ValidInput(t *testing.T) {

	random := []byte{
		0x6f, 0x98, 0x03, 0x8c, 0x08, 0x3e, 0xa1, 0x51, 0x38, 0x1e, 0x0f, 0x4b,
		0xec, 0xb7, 0x45, 0x0c, 0x52, 0xf5, 0x03, 0x7a, 0x33, 0x39, 0xd9, 0x67,
		0xf9, 0x5c, 0x38, 0xba, 0x2a, 0x6a, 0x31, 0x16,
	}

	sessionId := []byte(nil)

	cipherSuites := []spec.CipherSuite{spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}

	pointFormatsValues := []byte{byte(spec.ECPointFormatUncompressed)}
	pointFormats, _ := NewOpaqueVector8(pointFormatsValues)

	supportedGroupsValues := make([]byte, 2)
	binary.BigEndian.PutUint16(supportedGroupsValues, uint16(spec.SupportedGroupsSecp256r1))
	supportedGroups, _ := NewOpaqueVector16(supportedGroupsValues)

	supportedSignatureAlgorithmsValues := make([]byte, 2)
	binary.BigEndian.PutUint16(supportedSignatureAlgorithmsValues, uint16(spec.SignatureAlgorithmRsaPkcs1Sha256))
	supportedSignatureAlgorithms, _ := NewOpaqueVector16(supportedSignatureAlgorithmsValues)

	extensions := []spec.Extension{
		{
			Type:   spec.ExtensionTypeECPointFormats,
			Opaque: pointFormats,
		},
		{
			Type:   spec.ExtensionTypeSupportedGroups,
			Opaque: supportedGroups,
		},
		{
			Type:   spec.ExtensionTypeSessionTicket,
			Opaque: []byte(nil),
		},
		{
			Type:   spec.ExtensionTypeSignatureAlgorithms,
			Opaque: supportedSignatureAlgorithms,
		},
	}

	clientHello, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	rawClientHello := MarshalClientHello(clientHello)

	expectedRawClientHello := []byte{
		0x03, 0x03, 0x6f, 0x98, 0x03, 0x8c, 0x08, 0x3e, 0xa1, 0x51, 0x38, 0x1e,
		0x0f, 0x4b, 0xec, 0xb7, 0x45, 0x0c, 0x52, 0xf5, 0x03, 0x7a, 0x33, 0x39,
		0xd9, 0x67, 0xf9, 0x5c, 0x38, 0xba, 0x2a, 0x6a, 0x31, 0x16, 0x00, 0x00,
		0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x1a, 0x00, 0x0a, 0x00, 0x04, 0x00,
		0x02, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00,
		0x04, 0x00, 0x02, 0x04, 0x01, 0x00, 0x23, 0x00, 0x00,
	}

	if len(rawClientHello) != len(expectedRawClientHello) {
		t.Fatalf("raw client hello length mismatch: expected %v, got %v", len(expectedRawClientHello), len(rawClientHello))
	}

	for i := range len(expectedRawClientHello) {
		if rawClientHello[i] != expectedRawClientHello[i] {
			t.Fatalf("raw client hello mismatch at index %v: expected %v, got %v", i, expectedRawClientHello[i], rawClientHello[i])
		}
	}
}
