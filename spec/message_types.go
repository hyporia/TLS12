package spec

type MessageType byte

const (
	MessageTypeClientHello MessageType = 0x01
	MessageTypeServerHello MessageType = 0x02
)
