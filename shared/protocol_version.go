package shared

import (
	"fmt"
)

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
