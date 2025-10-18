package utils

import (
	"fmt"

	"github.com/piligrimm/tls/spec"
)

func ParseProtocolVersionFromRawPayload(rawProtocolVersion []byte) (*spec.ProtocolVersion, error) {
	if len(rawProtocolVersion) != 2 {
		return nil, fmt.Errorf("protocol payload has incorrect length")
	}

	tls12ProtocolVersion := spec.Tls12ProtocolVersion()

	if rawProtocolVersion[0] != tls12ProtocolVersion.Major || rawProtocolVersion[1] != tls12ProtocolVersion.Minor {
		return nil, fmt.Errorf("incorrect protocol version")
	}

	return &tls12ProtocolVersion, nil
}
