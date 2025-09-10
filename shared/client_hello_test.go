// File: shared/client_hello_test.go
package shared

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"time"
)

func TestCreateClientHello_ValidInput(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix())) // Valid timestamp
	sessionId := []byte{0x01, 0x02}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
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
	if err.Error() != "unsupported cipher suite: CipherSuite(0x1337)" {
		t.Errorf("Expected error message 'unsupported cipher suite', got %q", err.Error())
	}
}

func TestCreateClientHello_DuplicateExtension(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()))
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
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
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
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
