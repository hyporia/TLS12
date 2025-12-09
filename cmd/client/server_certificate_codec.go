package main

import (
	"crypto/x509"
	"fmt"

	"github.com/piligrimm/tls/spec"
)

func UnmarshalServerCertificate(serverCertificateRaw []byte) (*spec.Certificate, error) {
	off := 0
	need := func(n int) error {
		if off+n > len(serverCertificateRaw) {
			return fmt.Errorf("truncated ServerCertificate at offset %d, need %d bytes", off, n)
		}
		return nil
	}

	if err := need(3); err != nil {
		return nil, err
	}

	certificatesLength := int(serverCertificateRaw[0])<<16 | int(serverCertificateRaw[1])<<8 | int(serverCertificateRaw[2])

	fmt.Printf("Certificates length: %d\n", certificatesLength)
	off += 3
	certificatesRaw := serverCertificateRaw[off : off+certificatesLength]

	var derConcat []byte
	for curCertOff := 0; curCertOff < certificatesLength; {
		if certificatesLength-curCertOff < 3 {
			return nil, fmt.Errorf("truncated cert_length")
		}
		certLen := int(certificatesRaw[curCertOff])<<16 | int(certificatesRaw[curCertOff+1])<<8 | int(certificatesRaw[curCertOff+2])
		curCertOff += 3
		if len(certificatesRaw)-curCertOff < certLen {
			return nil, fmt.Errorf("truncated certificate")
		}
		derConcat = append(derConcat, certificatesRaw[curCertOff:curCertOff+certLen]...)
		curCertOff += certLen
	}
	certificates, err := x509.ParseCertificates(derConcat)

	if err != nil {
		return nil, err
	}

	return &spec.Certificate{
		Cetificates: certificates,
	}, nil
}
