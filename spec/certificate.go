package spec

import "crypto/x509"

type ServerCertificate struct {
	Certificates []*x509.Certificate
}
