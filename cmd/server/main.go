package main

import (
	"net"
)

func main() { // coverage-ignore
	listener, err := net.Listen("tcp", "127.0.0.1:6969")

	if err != nil {
		panic(err)
	}

	_, _ = listener.Accept()
}
