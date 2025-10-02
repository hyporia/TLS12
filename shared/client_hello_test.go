// File: shared/client_hello_test.go
package shared

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestCreateClientHello_ValidInput(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix())) // Valid timestamp
	sessionId := []byte{0x01, 0x02}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []Extension{}

	// Act
	clientHello, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if clientHello == nil {
		t.Fatal("Expected non-nil ClientHello")
	}
	if len(clientHello.random) != 32 {
		t.Errorf("Expected random to be 32 bytes, got %d", len(clientHello.random))
	}
	if len(clientHello.sessionId) != 2 {
		t.Errorf("Expected session ID to be 2 bytes, got %d", len(clientHello.sessionId))
	}
	if len(clientHello.cipherSuites) != 1 {
		t.Errorf("Expected 1 cipher suite, got %d", len(clientHello.cipherSuites))
	}
	if len(clientHello.extensions) != 0 {
		t.Errorf("Expected no extensions, got %d", len(clientHello.extensions))
	}
}

func TestCreateClientHello_InvalidRandomLength(t *testing.T) {
	// Arrange
	random := make([]byte, 31) // Too short
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
	extensions := []Extension{}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for invalid random length")
	}
	if err.Error() != "random must contain 32 bytes" {
		t.Errorf("Expected error message 'random must contain 32 bytes', got %q", err.Error())
	}
}

func TestCreateClientHello_UnsupportedCipherSuite(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()))
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuite(0x1337)} // Invalid
	extensions := []Extension{}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for unsupported cipher suite")
	}
	expectedErrorMessage := "unsupported cipher suite: CipherSuite(0x1337)"
	if err.Error() != expectedErrorMessage {
		t.Errorf("Expected error message '%s', got %q", expectedErrorMessage, err.Error())
	}
}

func TestCreateClientHello_DuplicateExtension(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()))
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []Extension{
		{Type: ExtensionTypeServerName, Opaque: []byte{}},
		{Type: ExtensionTypeServerName, Opaque: []byte{}}, // Duplicate
	}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for duplicate extension")
	}
	if err.Error() != "duplicate extension: ServerName" {
		t.Errorf("Expected error message 'duplicate extension: ServerName', got %q", err.Error())
	}
}

func TestCreateClientHello_UnsupportedExtension(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()))
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []Extension{
		{Type: ExtensionType(0x1337), Opaque: []byte{}}, // Unknown type
	}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for unsupported extension")
	}
	if err.Error() != "unsupported extension ExtensionType(0x1337)" {
		t.Errorf("Expected error message 'unsupported extension 0x1337', got %q", err.Error())
	}
}

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

	if clientHello.clientVersion.major != Tls12ProtocolVersion().major || clientHello.clientVersion.minor != Tls12ProtocolVersion().minor {
		t.Errorf("Expected TLS 1.2 version(3, 3), got %d.%d", clientHello.clientVersion.major, clientHello.clientVersion.minor)
	}

	expectedRandom := []byte{
		0x6f, 0x98, 0x03, 0x8c, 0x08, 0x3e, 0xa1, 0x51,
		0x38, 0x1e, 0x0f, 0x4b, 0xec, 0xb7, 0x45, 0x0c,
		0x52, 0xf5, 0x03, 0x7a, 0x33, 0x39, 0xd9, 0x67,
		0xf9, 0x5c, 0x38, 0xba, 0x2a, 0x6a, 0x31, 0x16,
	}
	if !bytes.Equal(clientHello.random, expectedRandom) {
		t.Errorf("Unexpected random: %x", clientHello.random)
	}

	if len(clientHello.sessionId) != 0 {
		t.Errorf("Expected empty session ID, got %x", clientHello.sessionId)
	}

	expectedCipherSuites := []CipherSuite{
		CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384,
		CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA,
		CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		CipherSuiteDHE_RSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA256,
		CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA,
		CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT,
		CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
		CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
		CipherSuiteGOSTR341001_WITH_28147_CNT_IMIT,
		CipherSuiteRSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteRSA_WITH_AES_256_CBC_SHA256,
		CipherSuiteRSA_WITH_AES_256_CBC_SHA,
		CipherSuiteRSA_WITH_CAMELLIA_256_CBC_SHA256,
		CipherSuiteDH_anon_WITH_CAMELLIA_128_GCM_SHA256,
		CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256,
		CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA,
		CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		CipherSuiteDHE_RSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA256,
		CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA,
		CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
		CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
		CipherSuiteRSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteRSA_WITH_AES_128_CBC_SHA256,
		CipherSuiteRSA_WITH_AES_128_CBC_SHA,
		CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA256,
		CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA,
		CipherSuiteECDHE_RSA_WITH_RC4_128_SHA,
		CipherSuiteECDHE_ECDSA_WITH_RC4_128_SHA,
		CipherSuiteRSA_WITH_RC4_128_SHA,
		CipherSuiteRSA_WITH_RC4_128_MD5,
		CipherSuiteECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CipherSuiteECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
		CipherSuiteDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CipherSuiteRSA_WITH_3DES_EDE_CBC_SHA,
		CipherSuiteEMPTY_RENEGOTIATION_INFO_SCSV,
	}

	if len(clientHello.cipherSuites) != len(expectedCipherSuites) {
		t.Fatalf("Expected %d cipher suites, got %d", len(expectedCipherSuites), len(clientHello.cipherSuites))
	}

	for i, suite := range expectedCipherSuites {
		if clientHello.cipherSuites[i] != suite {
			t.Fatalf("Cipher suite mismatch at position %d: expected %v, got %v", i, suite, clientHello.cipherSuites[i])
		}
	}

	if len(clientHello.compression) != 1 || clientHello.compression[0] != 0x00 {
		t.Errorf("Expected only null compression, got %x", clientHello.compression)
	}

	expectedExtensions := []Extension{
		{Type: ExtensionTypeECPointFormats, Opaque: []byte{0x01, 0x00}},
		{Type: ExtensionTypeSupportedGroups, Opaque: []byte{0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}},
		{Type: ExtensionTypeSessionTicket, Opaque: nil},
		{Type: ExtensionTypeSignatureAlgorithms, Opaque: []byte{0x00, 0x16, 0x08, 0x06, 0x06, 0x01, 0x06, 0x03, 0x08, 0x05, 0x05, 0x01, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03}},
	}

	if len(clientHello.extensions) != len(expectedExtensions) {
		t.Fatalf("Expected %d extensions, got %d", len(expectedExtensions), len(clientHello.extensions))
	}

	for i, ext := range expectedExtensions {
		got := clientHello.extensions[i]
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

	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}

	pointFormatsValues := []byte{byte(ECPointFormatUncompressed)}
	pointFormats, _ := NewOneByteLengthOpaque(pointFormatsValues)

	supportedGroupsValues := make([]byte, 2)
	binary.BigEndian.PutUint16(supportedGroupsValues, uint16(SupportedGroupsSecp256r1))
	supportedGroups, _ := NewTwoBytesLengthOpaque(supportedGroupsValues)

	supportedSignatureAlgorithmsValues := make([]byte, 2)
	binary.BigEndian.PutUint16(supportedSignatureAlgorithmsValues, uint16(SignatureAlgorithmRsaPkcs1Sha256))
	supportedSignatureAlgorithms, _ := NewTwoBytesLengthOpaque(supportedSignatureAlgorithmsValues)

	extensions := []Extension{
		{
			Type:   ExtensionTypeECPointFormats,
			Opaque: pointFormats,
		},
		{
			Type:   ExtensionTypeSupportedGroups,
			Opaque: supportedGroups,
		},
		{
			Type:   ExtensionTypeSessionTicket,
			Opaque: []byte(nil),
		},
		{
			Type:   ExtensionTypeSignatureAlgorithms,
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
		0x02, 0xc0, 0x2f, 0x01, 0x00, 0x00, 0x1a, 0x00, 0x0b, 0x00, 0x02, 0x01,
		0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17, 0x00, 0x23, 0x00,
		0x00, 0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x04, 0x01,
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
