package shared

import (
	"fmt"
)

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
