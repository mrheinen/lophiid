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
package network

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// The max amount of bytes to read from a TCP connection.
var MaxTcpReadBufferSize = 1024 * 25

// The max amount of bytes to read from a UDP connection.
var MaxUdpReadBufferSize = 1024 * 25

var (
	ErrResolve    = errors.New("resolve error")
	ErrRead       = errors.New("read error")
	ErrConnection = errors.New("connection error")
	ErrDial       = errors.New("dial error")
)

// ReadDataFromTcp reads data from a TCP connection at the specified IP address and port.
func ReadDataFromTcp(address string, port int64, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.FormatInt(port, 10)), timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDial, err)
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
		return nil, fmt.Errorf("%w: %w", ErrRead, err)
	}

	return data[:n], nil
}

// ReadDataFromUdp reads data from a UDP connection at the specified IP address and port.
func ReadDataFromUdp(address string, port int64, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(address, strconv.FormatInt(port, 10)), timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDial, err)
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, fmt.Errorf("setting deadline: %w", err)
	}

	// Read data from the connection
	data := make([]byte, MaxUdpReadBufferSize)
	n, err := conn.Read(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRead, err)
	}

	return data[:n], nil
}
