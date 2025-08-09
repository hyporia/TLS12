// src/shared/types.go
package shared

import "fmt"

type CipherSuite uint16

const (
	// ECDHE with ECDSA
	CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc009
	CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc00a
	CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9

	// ECDHE with RSA
	CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc013
	CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc014
	CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02f
	CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc030
	CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca8
)

// Returns a slice of all supported cipher suites
func SupportedCipherSuites() []CipherSuite {
	return []CipherSuite{
		CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA,
		CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA,
		CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

type ExtensionType uint16

const (
	ExtensionTypeServerName           ExtensionType = 0x0000
	ExtensionTypeSupportedGroups      ExtensionType = 0x000a // previously called elliptic_curves
	ExtensionTypeECPointFormats       ExtensionType = 0x000b
	ExtensionTypeSignatureAlgorithms  ExtensionType = 0x000d
	ExtensionTypeRenegotiationInfo    ExtensionType = 0xff01
	ExtensionTypeExtendedMasterSecret ExtensionType = 0x0017
)

func ExtensionTypes() []ExtensionType {
	return []ExtensionType{
		ExtensionTypeServerName,
		ExtensionTypeSupportedGroups,
		ExtensionTypeECPointFormats,
		ExtensionTypeSignatureAlgorithms,
		ExtensionTypeRenegotiationInfo,
		ExtensionTypeExtendedMasterSecret,
	}
}

type ProtocolVersion struct {
	Major uint8 // 0x03 for TLS 1.x
	Minor uint8 // 0x03 for TLS 1.2
}

type Extensions struct {
	Type   ExtensionType
	Opaque []byte
}

func (c CipherSuite) String() string {
	switch c {
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("CipherSuite(0x%04x)", uint16(c))
	}
}

func (e ExtensionType) String() string {
	switch e {
	case ExtensionTypeServerName:
		return "ServerName"
	case ExtensionTypeSupportedGroups:
		return "SupportedGroups"
	case ExtensionTypeECPointFormats:
		return "ECPointFormats"
	case ExtensionTypeSignatureAlgorithms:
		return "SignatureAlgorithms"
	case ExtensionTypeRenegotiationInfo:
		return "RenegotiationInfo"
	case ExtensionTypeExtendedMasterSecret:
		return "ExtendedMasterSecret"
	default:
		return fmt.Sprintf("ExtensionType(0x%04x)", uint16(e))
	}
}
