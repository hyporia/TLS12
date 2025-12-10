package main

import (
	"crypto/x509"
	"fmt"

	"github.com/piligrimm/tls/spec"
)

func UnmarshalServerCertificate(raw []byte) (*spec.ServerCertificate, error) {
	checkOffset := func(required int) error {
		if required < 0 || len(raw) < required+3 {
			return fmt.Errorf("truncated ServerCertificate at offset %d", required)
		}
		return nil
	}

	if err := checkOffset(0); err != nil {
		return nil, err
	}
	totalCertLength := int(raw[0])<<16 | int(raw[1])<<8 | int(raw[2])
	fmt.Printf("Total certificates length: %d bytes\n", totalCertLength)

	if err := checkOffset(totalCertLength - 3); err != nil {
		return nil, err
	}

	certificatesRaw := raw[3 : 3+totalCertLength]
	var certificates []*x509.Certificate

	for curCertOff := 0; curCertOff < len(certificatesRaw); {
		if err := checkOffset(curCertOff); err != nil {
			return nil, err
		}

		certLen := int(certificatesRaw[curCertOff])<<16 | int(certificatesRaw[curCertOff+1])<<8 | int(certificatesRaw[curCertOff+2])
		curCertOff += 3

		if curCertOff > len(certificatesRaw)-certLen {
			return nil, fmt.Errorf("truncated certificate at offset %d", curCertOff)
		}

		derBytes := certificatesRaw[curCertOff : curCertOff+certLen]
		curCertOff += certLen

		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at offset %d: %v", curCertOff-certLen-3, err)
		}

		certificates = append(certificates, cert)
	}

	return &spec.ServerCertificate{
		Certificates: certificates,
	}, nil
}
