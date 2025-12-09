package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"github.com/piligrimm/tls/spec"
)

func TestCreateServerHello_ValidInput(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	rand.Read(random)
	binary.BigEndian.PutUint32(random[:4], uint32(time.Now().Unix())) // Valid timestamp
	sessionID := []byte{0x01, 0x02}
	cipherSuite := spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions := []spec.Extension{}

	// Act
	serverHello, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if serverHello == nil {
		t.Fatal("Expected non-nil ServerHello")
	}
	if len(serverHello.Random) != 32 {
		t.Errorf("Expected random to be 32 bytes, got %d", len(serverHello.Random))
	}
	if !bytes.Equal(random, serverHello.Random) {
		t.Errorf("Expected random to be equal, got %v", serverHello.Random)
	}
	if len(serverHello.SessionID) != 2 {
		t.Errorf("Expected session ID to be 2 bytes, got %d", len(serverHello.SessionID))
	}
	if serverHello.CipherSuite != cipherSuite {
		t.Errorf("Expected cipher suite %v, got %v", cipherSuite, serverHello.CipherSuite)
	}
	if len(serverHello.Extensions) != 0 {
		t.Errorf("Expected no extensions, got %d", len(serverHello.Extensions))
	}
}

func TestCreateServerHello_InvalidRandomLength(t *testing.T) {
	// Arrange
	random := make([]byte, 31) // Too short
	sessionID := []byte{}
	cipherSuite := spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions := []spec.Extension{}

	// Act
	_, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for invalid random length")
	}
	if err.Error() != "random must contain 32 bytes" {
		t.Errorf("Expected error message 'random must contain 32 bytes', got %q", err.Error())
	}
}

func TestCreateServerHello_UnsupportedCipherSuite(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	sessionID := []byte{}
	cipherSuite := spec.CipherSuite(0x1337) // Invalid
	extensions := []spec.Extension{}

	// Act
	_, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for unsupported cipher suite")
	}
	expectedErrorMessage := "unsupported cipher suite: CipherSuite(0x1337)"
	if err.Error() != expectedErrorMessage {
		t.Errorf("Expected error message '%s', got %q", expectedErrorMessage, err.Error())
	}
}

func TestCreateServerHello_SessionIdTooLong(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	sessionID := make([]byte, 33) // Too long - exceeds 32 bytes
	cipherSuite := spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions := []spec.Extension{}

	// Act
	_, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for session ID too long")
	}

	expectedMessage := "session ID cannot be longer than 32 bytes"
	if err.Error() != expectedMessage {
		t.Errorf("Expected error message '%q', got '%q'", expectedMessage, err.Error())
	}
}

func TestCreateServerHello_DuplicateExtension(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	sessionID := []byte{}
	cipherSuite := spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions := []spec.Extension{
		{Type: spec.ExtensionTypeServerName, Opaque: []byte{}},
		{Type: spec.ExtensionTypeServerName, Opaque: []byte{}}, // Duplicate
	}

	// Act
	_, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for duplicate extension")
	}
	if err.Error() != "duplicate extension: ServerName" {
		t.Errorf("Expected error message 'duplicate extension: ServerName', got %q", err.Error())
	}
}

func TestCreateServerHello_UnsupportedExtension(t *testing.T) {
	// Arrange
	random := make([]byte, 32)
	sessionID := []byte{}
	cipherSuite := spec.CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256
	extensions := []spec.Extension{
		{Type: spec.ExtensionType(0x1337), Opaque: []byte{}}, // Unknown type
	}

	// Act
	_, err := NewServerHello(random, sessionID, cipherSuite, extensions)

	// Assert
	if err == nil {
		t.Fatal("Expected error for unsupported extension")
	}
	if err.Error() != "unsupported extension ExtensionType(0x1337)" {
		t.Errorf("Expected error message 'unsupported extension ExtensionType(0x1337)', got %q", err.Error())
	}
}
