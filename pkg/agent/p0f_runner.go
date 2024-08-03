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
package agent

import (
	"errors"
	"fmt"
	"net"

	"github.com/mrheinen/p0fclient"
)

// ErrNoResult is returned when no result is received
var ErrP0fQueryNoResult = fmt.Errorf("got no result")

type P0fRunner interface {
	QueryIP(ip string) (*p0fclient.Response, error)
}

type P0fRunnerImpl struct {
	client *p0fclient.P0fClient
}

func (p *P0fRunnerImpl) Start() error {
	return p.client.Connect()
}

// NewP0fRunnerImpl creates a new P0fRunner. The client needs to have been
// initialized and Connect() has to have been called and checked already.
func NewP0fRunnerImpl(client *p0fclient.P0fClient) *P0fRunnerImpl {
	return &P0fRunnerImpl{
		client: client,
	}
}

func (p P0fRunnerImpl) QueryIP(ip string) (*p0fclient.Response, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &p0fclient.Response{}, fmt.Errorf("could not parse IP: %s", ip)
	}

	result, err := p.client.QueryIP(parsedIP)

	if errors.Is(err, p0fclient.ErrSocketCommunication) {
		// In this case perhaps p0f restarted or is not listening anymore on the
		// socket. We try to reconnect so that the next query *might* succeed.
		if serr := p.Start(); err != nil {
			return &p0fclient.Response{}, fmt.Errorf("could not reconnect: %w", serr)
		}

		return &p0fclient.Response{}, fmt.Errorf("p0f communication error: %w", err)
	}

	if result.Status == p0fclient.P0F_STATUS_NOMATCH {
		return &p0fclient.Response{}, ErrP0fQueryNoResult
	}
	return result, nil
}

// For testing
type FakeP0fRunnerImpl struct {
	ResponseToReturn *p0fclient.Response
	ErrorToReturn    error
}

func (f *FakeP0fRunnerImpl) QueryIP(ip string) (*p0fclient.Response, error) {
	return f.ResponseToReturn, f.ErrorToReturn
}
