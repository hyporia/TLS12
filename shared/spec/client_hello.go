package spec

type ClientHello struct {
	ClientVersion ProtocolVersion
	Random        []byte
	SessionID     []byte
	CipherSuites  []CipherSuite
	Compression   []byte
	Extensions    []Extension
}
