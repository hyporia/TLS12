package spec

type ClientHello struct {
	ClientTlsVersion   ProtocolVersion
	Random             []byte
	SessionID          []byte
	CipherSuites       []CipherSuite
	CompressionMethods []CompressionMethod
	Extensions         []Extension
}
