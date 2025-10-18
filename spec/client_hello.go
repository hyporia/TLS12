package spec

type ClientHello struct {
	ClientVersion      ProtocolVersion
	Random             []byte
	SessionID          []byte
	CipherSuites       []CipherSuite
	CompressionMethods []CompressionMethod
	Extensions         []Extension
}
