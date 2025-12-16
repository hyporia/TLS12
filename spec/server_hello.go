package spec

type ServerHello struct {
	ServerTlsVersion  ProtocolVersion
	Random            []byte
	SessionID         []byte
	CipherSuite       CipherSuite
	CompressionMethod CompressionMethod
	Extensions        []Extension
}
