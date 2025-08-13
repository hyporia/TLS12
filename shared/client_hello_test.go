// File: shared/client_hello_test.go
package shared

import (
	"encoding/binary"
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
	if len(clientHello.Random()) != 32 {
		t.Errorf("Expected random to be 32 bytes, got %d", len(clientHello.Random()))
	}
	if len(clientHello.SessionId()) != 2 {
		t.Errorf("Expected session ID to be 2 bytes, got %d", len(clientHello.SessionId()))
	}
	if len(clientHello.CipherSuites()) != 1 {
		t.Errorf("Expected 1 cipher suite, got %d", len(clientHello.CipherSuites()))
	}
	if len(clientHello.Extensions()) != 0 {
		t.Errorf("Expected no extensions, got %d", len(clientHello.Extensions()))
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
	if err.Error() != "'random' must contain 32 bytes" {
		t.Errorf("Expected error message 'random must contain 32 bytes', got %q", err.Error())
	}
}

func TestCreateClientHello_TimestampTooOld(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()-120)) // 2 minutes ago
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
	extensions := []Extension{}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for timestamp too old")
	}
	if err.Error() != "timestamp in 'random' cannot be more than an minute old" {
		t.Errorf("Expected error message 'timestamp cannot be more than an minute old', got %q", err.Error())
	}
}

func TestCreateClientHello_TimestampInFuture(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix()+10)) // 10 seconds in future
	sessionId := []byte{}
	cipherSuites := []CipherSuite{CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA}
	extensions := []Extension{}

	// Act
	_, err := NewClientHello(random, sessionId, cipherSuites, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for timestamp in future")
	}
	if err.Error() != "timestamp in 'random' cannot be in the future" {
		t.Errorf("Expected error message 'timestamp cannot be in the future', got %q", err.Error())
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
	if err.Error() != "unsupported cipher suite" {
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
	if err.Error() != "duplicate extension: 'ServerName'" {
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
	if err.Error() != "unsupported extension 'ExtensionType(0x1337)'" {
		t.Errorf("Expected error message 'unsupported extension 0x1337', got %q", err.Error())
	}
}
