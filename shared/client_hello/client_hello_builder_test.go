package client_hello

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/piligrimm/tls/shared/spec"
)

func TestCreateClientHello_ValidInput(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix())) // Valid timestamp
	sessionID := []byte{0x01, 0x02}
	cipherSuites := []spec.CipherSuite{spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []spec.Extension{}

	// Act
	clientHello, err := NewClientHello(random, sessionID, cipherSuites, extensions)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if clientHello == nil {
		t.Fatal("Expected non-nil ClientHello")
	}
	if len(clientHello.Random) != 32 {
		t.Errorf("Expected random to be 32 bytes, got %d", len(clientHello.Random))
	}
	if len(clientHello.SessionID) != 2 {
		t.Errorf("Expected session ID to be 2 bytes, got %d", len(clientHello.SessionID))
	}
	if len(clientHello.CipherSuites) != 1 {
		t.Errorf("Expected 1 cipher suite, got %d", len(clientHello.CipherSuites))
	}
	if len(clientHello.Extensions) != 0 {
		t.Errorf("Expected no extensions, got %d", len(clientHello.Extensions))
	}
}

func TestCreateClientHello_InvalidRandomLength(t *testing.T) {
	// Arrange
	random := make([]byte, 31) // Too short
	sessionID := []byte{}
	cipherSuites := []spec.CipherSuite{spec.CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
	extensions := []spec.Extension{}

	// Act
	_, err := NewClientHello(random, sessionID, cipherSuites, extensions)

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
	sessionID := []byte{}
	cipherSuites := []spec.CipherSuite{spec.CipherSuite(0x1337)} // Invalid
	extensions := []spec.Extension{}

	// Act
	_, err := NewClientHello(random, sessionID, cipherSuites, extensions)

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
	sessionID := []byte{}
	cipherSuites := []spec.CipherSuite{spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []spec.Extension{
		{Type: spec.ExtensionTypeServerName, Opaque: []byte{}},
		{Type: spec.ExtensionTypeServerName, Opaque: []byte{}}, // Duplicate
	}

	// Act
	_, err := NewClientHello(random, sessionID, cipherSuites, extensions)

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
	sessionID := []byte{}
	cipherSuites := []spec.CipherSuite{spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256}
	extensions := []spec.Extension{
		{Type: spec.ExtensionType(0x1337), Opaque: []byte{}}, // Unknown type
	}

	// Act
	_, err := NewClientHello(random, sessionID, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for unsupported extension")
	}
	if err.Error() != "unsupported extension ExtensionType(0x1337)" {
		t.Errorf("Expected error message 'unsupported extension ExtensionType(0x1337)', got %q", err.Error())
	}
}
