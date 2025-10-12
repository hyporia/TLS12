package spec

import "fmt"

type CipherSuite uint16

const (
	CipherSuiteEMPTY_RENEGOTIATION_INFO_SCSV CipherSuite = 0x00ff

	// To implement
	CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256 CipherSuite = 0xc02f

	// ECDHE with ECDSA
	CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc009
	CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc00a
	CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256       CipherSuite = 0xc02b
	CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc02c
	CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca9

	CipherSuiteECDHE_ECDSA_WITH_RC4_128_SHA            CipherSuite = 0xc007
	CipherSuiteECDHE_RSA_WITH_RC4_128_SHA              CipherSuite = 0xc011
	CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA          CipherSuite = 0xc013
	CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA          CipherSuite = 0xc014
	CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256     CipherSuite = 0xc023
	CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384     CipherSuite = 0xc024
	CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256       CipherSuite = 0xc027
	CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384       CipherSuite = 0xc028
	CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384       CipherSuite = 0xc030
	CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite = 0xcca8
	CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   CipherSuite = 0xccaa

	CipherSuiteGOSTR341112_256_WITH_28147_CNT_IMIT      CipherSuite = 0xc102
	CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT CipherSuite = 0xff85

	CipherSuiteDHE_RSA_WITH_AES_256_GCM_SHA384      CipherSuite = 0x009f
	CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA256      CipherSuite = 0x006b
	CipherSuiteDHE_RSA_WITH_AES_256_CBC_SHA         CipherSuite = 0x0039
	CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 CipherSuite = 0x00c4
	CipherSuiteDHE_RSA_WITH_CAMELLIA_256_CBC_SHA    CipherSuite = 0x0088
	CipherSuiteGOSTR341094_WITH_28147_CNT_IMIT      CipherSuite = 0x0080
	CipherSuiteGOSTR341001_WITH_28147_CNT_IMIT      CipherSuite = 0x0081
	CipherSuiteRSA_WITH_AES_256_GCM_SHA384          CipherSuite = 0x009d
	CipherSuiteRSA_WITH_AES_256_CBC_SHA256          CipherSuite = 0x003d
	CipherSuiteRSA_WITH_AES_256_CBC_SHA             CipherSuite = 0x0035
	CipherSuiteRSA_WITH_CAMELLIA_256_CBC_SHA256     CipherSuite = 0x00c0
	CipherSuiteDH_anon_WITH_CAMELLIA_128_GCM_SHA256 CipherSuite = 0x0084
	CipherSuiteDHE_RSA_WITH_AES_128_GCM_SHA256      CipherSuite = 0x009e
	CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA256      CipherSuite = 0x0067
	CipherSuiteDHE_RSA_WITH_AES_128_CBC_SHA         CipherSuite = 0x0033
	CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 CipherSuite = 0x00be
	CipherSuiteDHE_RSA_WITH_CAMELLIA_128_CBC_SHA    CipherSuite = 0x0045
	CipherSuiteRSA_WITH_AES_128_GCM_SHA256          CipherSuite = 0x009c
	CipherSuiteRSA_WITH_AES_128_CBC_SHA256          CipherSuite = 0x003c
	CipherSuiteRSA_WITH_AES_128_CBC_SHA             CipherSuite = 0x002f
	CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA256     CipherSuite = 0x00ba
	CipherSuiteRSA_WITH_CAMELLIA_128_CBC_SHA        CipherSuite = 0x0041
	CipherSuiteRSA_WITH_RC4_128_SHA                 CipherSuite = 0x0005
	CipherSuiteRSA_WITH_RC4_128_MD5                 CipherSuite = 0x0004
	CipherSuiteECDHE_RSA_WITH_3DES_EDE_CBC_SHA      CipherSuite = 0xc012
	CipherSuiteECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA    CipherSuite = 0xc008
	CipherSuiteDHE_RSA_WITH_3DES_EDE_CBC_SHA        CipherSuite = 0x0016
	CipherSuiteRSA_WITH_3DES_EDE_CBC_SHA            CipherSuite = 0x000a
)

func SupportedCipherSuites() []CipherSuite {
	return []CipherSuite{
		CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

func (c CipherSuite) String() string {
	switch c {
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case CipherSuiteECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case CipherSuiteECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case CipherSuiteECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case CipherSuiteECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case CipherSuiteECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case CipherSuiteECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case CipherSuiteECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	case CipherSuiteECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case CipherSuiteECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	case CipherSuiteDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case CipherSuiteGOSTR341112_256_WITH_28147_CNT_IMIT:
		return "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"
	case CipherSuiteDraftGOSTR341112_256_WITH_28147_CNT_IMIT:
		return "TLS_DRAFT_GOSTR341112_256_WITH_28147_CNT_IMIT"
	default:
		return fmt.Sprintf("CipherSuite(0x%04x)", uint16(c))
	}
}
