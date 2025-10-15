package spec

type Extension struct {
	Type   ExtensionType
	Opaque []byte
}

type Extensions []Extension
