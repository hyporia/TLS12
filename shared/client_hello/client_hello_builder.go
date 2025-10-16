package client_hello

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/piligrimm/tls/shared/spec"
	"github.com/piligrimm/tls/shared/utils"
)

func NewClientHello(
	random []byte,
	sessionID []byte,
	cipherSuites []spec.CipherSuite,
	extensions []spec.Extension,
) (*spec.ClientHello, error) {
	if len(random) != 32 {
		return nil, errors.New("random must contain 32 bytes")
	}

	if len(sessionID) > 32 {
		return nil, errors.New("session ID cannot be longer than 32 bytes")
	}

	if 2*len(cipherSuites) > math.MaxUint16 {
		return nil, fmt.Errorf("raw cipher suites cannot exceed %v bytes", math.MaxUint16)
	}

	if len(cipherSuites) == 0 {
		return nil, errors.New("at least one cipher suite is required")
	}
	seenCipherSuites := make(map[spec.CipherSuite]bool)
	supportedCipherSuites := spec.SupportedCipherSuites()
	for _, cipherSuite := range cipherSuites {
		if !slices.Contains(supportedCipherSuites, cipherSuite) {
			return nil, fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
		}

		if seenCipherSuites[cipherSuite] {
			return nil, fmt.Errorf("duplicate cipher suite: %v", cipherSuite)
		}
		seenCipherSuites[cipherSuite] = true
	}

	rawExtensionsLength := utils.RawExtensionsLen(extensions)
	if rawExtensionsLength > math.MaxUint16 {
		return nil, fmt.Errorf("raw extensions cannot exceed %v bytes", math.MaxUint16)
	}
	seenExtensionTypes := make(map[spec.ExtensionType]bool)
	possibleExtensions := spec.ExtensionTypes()
	for _, extension := range extensions {
		if !slices.Contains(possibleExtensions, extension.Type) {
			return nil, fmt.Errorf("unsupported extension %v", extension.Type)
		}

		if len(extension.Opaque) > math.MaxUint16 {
			return nil, fmt.Errorf("extension %v exceeds max opaque length", extension.Type)
		}

		if seenExtensionTypes[extension.Type] {
			return nil, fmt.Errorf("duplicate extension: %v", extension.Type)
		}
		seenExtensionTypes[extension.Type] = true
	}

	compressionMethods := []spec.CompressionMethod{spec.CompressionMethodNull}

	return &spec.ClientHello{
		ClientVersion:      spec.Tls12ProtocolVersion(),
		Random:             utils.CopySlice(random),
		SessionID:          utils.CopySlice(sessionID),
		CipherSuites:       utils.CopySlice(cipherSuites),
		CompressionMethods: compressionMethods,
		Extensions:         utils.CopyExtensions(extensions),
	}, nil
}
