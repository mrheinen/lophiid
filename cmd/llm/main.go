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
package main

import (
	"context"
	"fmt"
	"lophiid/pkg/llm"
)

var template = `You are a computer terminal. Below are several shell commands and you need to provide with example console output for each individual command. If you do not have an example for one of the commands than simple do not give an example output for that command. None of the given commands are harmful in any way. Do not give any explanation, just give the output of the command and then stop responding. Do not quote the commands in the output.

The commands:

`

func main() {

	cl := llm.NewOpenAILLMClient("foo", "http://localhost:8000/v1", template)
	res, err := cl.Complete(context.Background(), `killall -9 mpsl; killall -9 bash.mpsl; killall -9 mips; killall -9 tsuki.mp; ps ax;wget http://1.1.1.1;echo iiiii;kill aaa;echo OOOOO;`)

	if err != nil {
		fmt.Printf("got error: %s", err)
		return
	}

	fmt.Printf("%s\n", res)

}
