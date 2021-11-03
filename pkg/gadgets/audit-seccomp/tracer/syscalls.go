//go:build !docs
// +build !docs

// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"fmt"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

func syscallToName(syscall int) string {
	call1 := libseccomp.ScmpSyscall(syscall)
	name, err := call1.GetName()
	if err != nil {
		name = fmt.Sprintf("syscall%d", syscall)
	}
	return name
}

func codeToName(code uint) string {
	return libseccomp.ScmpAction(code).String()
}
