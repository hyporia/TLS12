package main

import "net"

func main() { // coverage-ignore
	listener, err := net.Listen("tcp", ":6969")

	if err != nil {
		panic(err)
	}

	_, _ = listener.Accept()
}
