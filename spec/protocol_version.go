package spec

type ProtocolVersion struct {
	Major uint8
	Minor uint8
}

func Tls12ProtocolVersion() ProtocolVersion {
	return ProtocolVersion{
		Major: 0x03,
		Minor: 0x03,
	}
}
