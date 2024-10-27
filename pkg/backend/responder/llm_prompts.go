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
You are a computer terminal and receive one command to execute. If you know the command then provide an example output. If the command is not known just provide an empty reply. Do not provide any analysis or description of the command. Just provide the output.

If a command contains the substring "$?" than replace that part of the command with the character 0.
If you echo a string, always add a newline at the end of the string unless echo is used with the -n flag.

The command is:
%s
`
var sourceCodeExecutionPrompt = `
You are a computer that is given source code. Tell me what output this source code produces. Just give the output and do not provide any analysis. If there is no output than simply give an empty reply.

%s
`
