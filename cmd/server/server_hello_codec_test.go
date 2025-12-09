package main

import (
	"bytes"
	"testing"

	"github.com/piligrimm/tls/spec"
)

func TestMarshalServerHello_ValidInput(t *testing.T) {
	random := []byte{
		0x68, 0xef, 0xa2, 0xcd, 0xb5, 0x7c, 0xd0, 0xac,
		0x98, 0x07, 0x3f, 0x2f, 0x8c, 0xd1, 0xc6, 0x5f,
		0x5c, 0x6a, 0xcd, 0x7a, 0xaa, 0xd9, 0xbc, 0x73,
		0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01,
	}

	extensions := []spec.Extension{
		{Type: spec.ExtensionTypeRenegotiationInfo, Opaque: []byte{0}},
		{Type: spec.ExtensionTypeECPointFormats, Opaque: []byte{1, 0}},
		{Type: spec.ExtensionTypeSessionTicket, Opaque: []byte(nil)},
	}

	serverHello := spec.ServerHello{
		ServerVersion:     spec.Tls12ProtocolVersion(),
		Random:            random,
		SessionID:         []byte(nil),
		CipherSuite:       spec.CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		CompressionMethod: spec.CompressionMethodNull,
		Extensions:        extensions,
	}

	rawServerHello := MarshalServerHello(&serverHello)

	expectedRawServerHello := []byte{
		0x03, 0x03, 0x68, 0xef, 0xa2, 0xcd, 0xb5, 0x7c,
		0xd0, 0xac, 0x98, 0x07, 0x3f, 0x2f, 0x8c, 0xd1,
		0xc6, 0x5f, 0x5c, 0x6a, 0xcd, 0x7a, 0xaa, 0xd9,
		0xbc, 0x73, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52,
		0x44, 0x01, 0x00, 0xcc, 0xa8, 0x00, 0x00, 0x0f,
		0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00,
		0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00,
	}

	if len(expectedRawServerHello) != len(rawServerHello) {
		t.Fatalf("raw server hello length mismatch: expected %v, got %v", len(expectedRawServerHello), len(rawServerHello))
	}

	for i := range expectedRawServerHello {
		if rawServerHello[i] != expectedRawServerHello[i] {
			t.Fatalf("raw server hello mismatch at index %v: expected %v, got %v", i, expectedRawServerHello[i], rawServerHello[i])
		}
	}
}

func TestUnmarshalServerHello_ValidInput(t *testing.T) {
	serverHelloRaw := []byte{
		0x03, 0x03, 0x68, 0xef, 0xa2, 0xcd, 0xb5, 0x7c,
		0xd0, 0xac, 0x98, 0x07, 0x3f, 0x2f, 0x8c, 0xd1,
		0xc6, 0x5f, 0x5c, 0x6a, 0xcd, 0x7a, 0xaa, 0xd9,
		0xbc, 0x73, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52,
		0x44, 0x01, 0x00, 0xcc, 0xa8, 0x00, 0x00, 0x0f,
		0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00,
		0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00,
	}

	serverHello, err := UnmarshalServerHello(serverHelloRaw)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if serverHello.ServerVersion != spec.Tls12ProtocolVersion() {
		t.Errorf("Expected ServerVersion %v, got %v", spec.Tls12ProtocolVersion(), serverHello.ServerVersion)
	}

	if len(serverHello.SessionID) > 0 {
		t.Errorf("Expected SessionID to be empty, got %v", serverHello.SessionID)
	}

	if serverHello.CipherSuite != spec.CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
		t.Errorf("Expected CipherSuite %v, got %v", spec.CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, serverHello.CipherSuite)
	}

	if serverHello.CompressionMethod != spec.CompressionMethodNull {
		t.Errorf("Expected CompressionMethod %v, got %v", spec.CompressionMethodNull, serverHello.CompressionMethod)
	}

	expectedRandom := []byte{
		0x68, 0xef, 0xa2, 0xcd, 0xb5, 0x7c, 0xd0, 0xac,
		0x98, 0x07, 0x3f, 0x2f, 0x8c, 0xd1, 0xc6, 0x5f,
		0x5c, 0x6a, 0xcd, 0x7a, 0xaa, 0xd9, 0xbc, 0x73,
		0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01,
	}

	if !bytes.Equal(serverHello.Random, expectedRandom) {
		t.Errorf("unexpected random: %x", serverHello.Random)
	}

	expectedExtensions := []spec.Extension{
		{Type: spec.ExtensionTypeRenegotiationInfo, Opaque: []byte{0}},
		{Type: spec.ExtensionTypeECPointFormats, Opaque: []byte{1, 0}},
		{Type: spec.ExtensionTypeSessionTicket, Opaque: []byte(nil)},
	}

	if len(serverHello.Extensions) != len(expectedExtensions) {
		t.Errorf("unexpected number of extensions: %d", len(serverHello.Extensions))
	}

	for i, ext := range expectedExtensions {
		got := serverHello.Extensions[i]
		if got.Type != ext.Type {
			t.Fatalf("Extension type mismatch at index %d: expected %v, got %v", i, ext.Type, got.Type)
		}
		if !bytes.Equal(got.Opaque, ext.Opaque) {
			t.Fatalf("Extension opaque mismatch at index %d: expected %x, got %x", i, ext.Opaque, got.Opaque)
		}
	}

}
