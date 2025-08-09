package shared

import (
	"encoding/binary"
	"errors"
	"slices"
	"time"
)

type ClientHello struct {
	msgType uint16

	clientVersion ProtocolVersion

	random []byte

	sessionId []byte

	cipherSuites []CipherSuite

	extensions []Extensions
}

func CreateClientHello(
	random []byte,
	sessionId []byte,
	cipherSuites []CipherSuite,
	extensions []Extensions,
) (*ClientHello, error) {

	if len(random) != 32 {
		return nil, errors.New("'random' must contain 32 bytes")
	}

	timestampFromRandom := binary.BigEndian.Uint32(random[:4])
	currentTimestamp := uint32(time.Now().Unix())
	minuteAgoTimestamp := currentTimestamp - 60

	if timestampFromRandom < minuteAgoTimestamp {
		return nil, errors.New("timestamp in 'random' cannot be more than an minute old")
	}

	if timestampFromRandom > currentTimestamp {
		return nil, errors.New("timestamp in 'random' cannot be in the future")
	}

	supportedCipherSuites := SupportedCipherSuites()
	for _, cipherSuite := range cipherSuites {
		if !slices.Contains(supportedCipherSuites, cipherSuite) {
			return nil, errors.New("unsupported cipher suite")
		}
	}

	return &ClientHello{
		msgType:       0x01,
		clientVersion: ProtocolVersion{Major: 0x03, Minor: 0x03},
		random:        random,
		sessionId:     sessionId,
		cipherSuites:  cipherSuites,
		extensions:    extensions,
	}, nil
}

func (clientHello *ClientHello) SessionId() []byte {
	return clientHello.sessionId
}
