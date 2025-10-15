package spec

type MessageType uint16

const (
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello MessageType = 0x02
)
