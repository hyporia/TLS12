package main

import "net"

func main() {
	listener, err := net.Listen("tcp", ":6969")

	if err != nil {
		panic(err)
	}

	_, _ = listener.Accept()
}
