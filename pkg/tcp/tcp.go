package tcp

import (
	"fmt"
	"net"
	"time"
)

// The max amount of bytes to read from a TCP connection.
var MaxTcpReadBufferSize = 1024 * 8

// ReadDataFromIPAddress reads data from a TCP connection at the specified IP address and port.
func ReadDataFromIPAddress(address string, port string, timeout time.Duration) ([]byte, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(address, port))
	if err != nil {
		return nil, fmt.Errorf("resolving tcp address: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("setting deadline: %w", err)
	}

	// Read data from the connection
	data := make([]byte, MaxTcpReadBufferSize)
	n, err := conn.Read(data)
	if err != nil {
		return nil, fmt.Errorf("reading data: %w", err)
	}

	return data[:n], nil
}
