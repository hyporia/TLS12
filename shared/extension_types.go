package shared

import "fmt"

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
