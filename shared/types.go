package shared

import (
	"fmt"
)

type MessageType uint16

const (
	MessageTypeClientHello MessageType = 0x01
)

type CipherSuite uint16

const (
	CipherSuiteEMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff

	// To implement
	CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256 CipherSuite = 0xc02f

	// ECDHE with ECDSA
	CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc009
	CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc00a
	CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9

	CipherSuiteECDHE_ECDSA_WITH_RC4_128_SHA            CipherSuite = 0xc007
	CipherSuiteECDHE_RSA_WITH_RC4_128_SHA              CipherSuite = 0xc011
	CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc013
	CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc014
	CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256     CipherSuite = 0xc023
	CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384     CipherSuite = 0xc024
	CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256       CipherSuite = 0xc027
	CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384       CipherSuite = 0xc028
	CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc030
	CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca8
	CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuite = 0xccaa

	CipherSuiteGOSTR341112_256_WITH_28147_CNT_IMIT      CipherSuite = 0xc102
	CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT CipherSuite = 0xff85

	CipherSuiteDHE_RSA_WITH_AES_256_GCM_SHA384      CipherSuite = 0x009f
	CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA256      CipherSuite = 0x006b
	CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA         CipherSuite = 0x0039
	CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 CipherSuite = 0x00c4
	CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA    CipherSuite = 0x0088
	CipherSuiteGOSTR341094_WITH_28147_CNT_IMIT      CipherSuite = 0x0080
	CipherSuiteGOSTR341001_WITH_28147_CNT_IMIT      CipherSuite = 0x0081
	CipherSuiteRSA_WITH_AES_256_GCM_SHA384          CipherSuite = 0x009d
	CipherSuiteRSA_WITH_AES_256_CBC_SHA256          CipherSuite = 0x003d
	CipherSuiteRSA_WITH_AES_256_CBC_SHA             CipherSuite = 0x0035
	CipherSuiteRSA_WITH_CAMELLIA_256_CBC_SHA256     CipherSuite = 0x00c0
	CipherSuiteDH_anon_WITH_CAMELLIA_128_GCM_SHA256 CipherSuite = 0x0084
	CipherSuiteDHE_RSA_WITH_AES_128_GCM_SHA256      CipherSuite = 0x009e
	CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA256      CipherSuite = 0x0067
	CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA         CipherSuite = 0x0033
	CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 CipherSuite = 0x00be
	CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA    CipherSuite = 0x0045
	CipherSuiteRSA_WITH_AES_128_GCM_SHA256          CipherSuite = 0x009c
	CipherSuiteRSA_WITH_AES_128_CBC_SHA256          CipherSuite = 0x003c
	CipherSuiteRSA_WITH_AES_128_CBC_SHA             CipherSuite = 0x002f
	CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA256     CipherSuite = 0x00ba
	CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA        CipherSuite = 0x0041
	CipherSuiteRSA_WITH_RC4_128_SHA                 CipherSuite = 0x0005
	CipherSuiteRSA_WITH_RC4_128_MD5                 CipherSuite = 0x0004
	CipherSuiteECDHE_RSA_WITH_3DES_EDE_CBC_SHA      CipherSuite = 0xc012
	CipherSuiteECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA    CipherSuite = 0xc008
	CipherSuiteDHE_RSA_WITH_3DES_EDE_CBC_SHA        CipherSuite = 0x0016
	CipherSuiteRSA_WITH_3DES_EDE_CBC_SHA            CipherSuite = 0x000a
)

// Returns a slice of all supported cipher suites
func SupportedCipherSuites() []CipherSuite {
	return []CipherSuite{
		CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

type SupportedGroup uint16

const (
	SupportedGroupsSecp256r1 SupportedGroup = 0x0017
)

type ECPointFormat uint8

const (
	ECPointFormatUncompressed            ECPointFormat = 0x00
	ECPointFormatAnsiX962CompressedPrime ECPointFormat = 0x01
	ECPointFormatAnsiX962CompressedChar2 ECPointFormat = 0x02
)

type SignatureAlgorithm uint16

const (
	SignatureAlgorithmRsaPkcs1Sha256 SignatureAlgorithm = 0x0401
	SignatureAlgorithmRsaPkcs1Sha384 SignatureAlgorithm = 0x0501
	SignatureAlgorithmRsaPkcs1Sha512 SignatureAlgorithm = 0x0601

	// ECDSA algorithms
	SignatureAlgorithmEcdsaSecp256r1Sha256 SignatureAlgorithm = 0x0403
	SignatureAlgorithmEcdsaSecp384r1Sha384 SignatureAlgorithm = 0x0503
	SignatureAlgorithmEcdsaSecp521r1Sha512 SignatureAlgorithm = 0x0603

	// RSASSA-PSS algorithms with public key OID rsaEncryption
	SignatureAlgorithmRsaPssRsaeSha256 SignatureAlgorithm = 0x0804
	SignatureAlgorithmRsaPssRsaeSha384 SignatureAlgorithm = 0x0805
	SignatureAlgorithmRsaPssRsaeSha512 SignatureAlgorithm = 0x0806

	// EdDSA algorithms
	SignatureAlgorithmEd25519 SignatureAlgorithm = 0x0807
	SignatureAlgorithmEd448   SignatureAlgorithm = 0x0808

	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	SignatureAlgorithmRsaPssPssSha256 SignatureAlgorithm = 0x0809
	SignatureAlgorithmRsaPssPssSha384 SignatureAlgorithm = 0x080a
	SignatureAlgorithmRsaPssPssSha512 SignatureAlgorithm = 0x080b

	// Legacy algorithms
	SignatureAlgorithmRsaPkcs1Sha1 SignatureAlgorithm = 0x0201
	SignatureAlgorithmEcdsaSha1    SignatureAlgorithm = 0x0203
)

type ExtensionType uint16

const (
	ExtensionTypeServerName           ExtensionType = 0x0000
	ExtensionTypeSupportedGroups      ExtensionType = 0x000a // previously called elliptic_curves
	ExtensionTypeECPointFormats       ExtensionType = 0x000b
	ExtensionTypeSignatureAlgorithms  ExtensionType = 0x000d
	ExtensionTypeSupportedVersions    ExtensionType = 0x002b
	ExtensionTypeRenegotiationInfo    ExtensionType = 0xff01
	ExtensionTypeExtendedMasterSecret ExtensionType = 0x0017
	ExtensionTypeSessionTicket        ExtensionType = 0x0023
)

func ExtensionTypes() []ExtensionType {
	return []ExtensionType{
		ExtensionTypeServerName,
		ExtensionTypeSupportedGroups,
		ExtensionTypeECPointFormats,
		ExtensionTypeSignatureAlgorithms,
		ExtensionTypeRenegotiationInfo,
		ExtensionTypeExtendedMasterSecret,
		ExtensionTypeSessionTicket,
	}
}

type ProtocolVersion struct {
	major uint8 // 0x03 for TLS 1.x
	minor uint8 // 0x03 for TLS 1.2
}

func Tls12ProtocolVersion() ProtocolVersion {
	return ProtocolVersion{
		major: 0x03,
		minor: 0x03,
	}
}

func parseProtocolVersionFromRawPayload(rawPayload []byte) (*ProtocolVersion, error) {
	if len(rawPayload) != 2 {
		return nil, fmt.Errorf("protocol payload has incorrect length")
	}

	tls12ProtocolVersion := Tls12ProtocolVersion()

	if rawPayload[0] != tls12ProtocolVersion.major || rawPayload[1] != tls12ProtocolVersion.minor {
		return nil, fmt.Errorf("incorrect protocol version")
	}

	return &tls12ProtocolVersion, nil
}

func Major(protocolVersion *ProtocolVersion) uint8 {
	return protocolVersion.major
}

func Minor(protocolVersion *ProtocolVersion) uint8 {
	return protocolVersion.minor
}

type Extension struct {
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
	case CipherSuiteECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
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
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case CipherSuiteGOSTR341112_256_WITH_28147_CNT_IMIT:
		return "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
	case CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT:
		return "TLS_DRAFT_GOSTR341112_256_WITH_28147_CNT_IMIT"

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
	case ExtensionTypeSupportedVersions:
		return "SupportedVersions"
	case ExtensionTypeSessionTicket:
		return "SessionTicket"
	default:
		return fmt.Sprintf("ExtensionType(0x%04x)", uint16(e))
	}
}

func (p ECPointFormat) String() string {
	switch p {
	case ECPointFormatUncompressed:
		return "Uncompressed"
	case ECPointFormatAnsiX962CompressedPrime:
		return "ANSI X962 Compressed Prime"
	case ECPointFormatAnsiX962CompressedChar2:
		return "ANSI X962 Compressed Char2"
	default:
		return fmt.Sprintf("ECPointFormat(0x%02x)", uint8(p))
	}
}
