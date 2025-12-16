package main

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/piligrimm/tls/internal/utils"
	"github.com/piligrimm/tls/spec"
)

func NewServerHello(
	random []byte,
	sessionID []byte,
	cipherSuite spec.CipherSuite,
	extensions []spec.Extension,
) (*spec.ServerHello, error) {
	if len(random) != 32 {
		return nil, errors.New("random must contain 32 bytes")
	}

	if len(sessionID) > 32 {
		return nil, errors.New("session ID cannot be longer than 32 bytes")
	}

	// todo: move this check to the client side
	supportedCipherSuites := spec.SupportedCipherSuites()
	if !slices.Contains(supportedCipherSuites, cipherSuite) {
		return nil, fmt.Errorf("unsupported cipher suite: %v", cipherSuite)
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

	return &spec.ServerHello{
		ServerTlsVersion:  spec.Tls12ProtocolVersion(),
		Random:            utils.CopySlice(random),
		SessionID:         utils.CopySlice(sessionID),
		CipherSuite:       cipherSuite,
		CompressionMethod: spec.CompressionMethodNull,
		Extensions:        utils.CopyExtensions(extensions),
	}, nil
}
