package spec

type ServerHello struct {
	ServerVersion     ProtocolVersion
	Random            []byte
	SessionID         []byte
	CipherSuite       CipherSuite
	CompressionMethod CompressionMethod
	Extensions        []Extension
}
