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
package responder

var commandInjectionPrompt = `
You are a computer terminal and receive a command-line command to execute. If you know the command-line command, which is written below, then provide an example output. If the command is not known just provide an empty reply. Do not provide any analysis, breakdown or description.

%s

`
var sourceCodeExecutionPrompt = `
You are a computer that is given source code. Tell me what output this source code produces. Just give the output and do not provide any analysis. If there is no output than simply give an empty reply.

%s
`

var helpfulAIPrompt = `You are a helpful AI. Please respond to the users request. Keep your answer straightforward and concise. This is the request: %s`
