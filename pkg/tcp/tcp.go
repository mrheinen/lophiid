// Lophiid distributed honeypot
// Copyright (C) 2024 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
//
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
