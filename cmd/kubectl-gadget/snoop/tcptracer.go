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

package snoop

import (
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/bcck8s"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/spf13/cobra"
)

var tcptracerCmd = &cobra.Command{
	Use:   "tcptracer",
	Short: "Trace tcp connect, accept and close",
	Run:   bcck8s.BccCmd("tcptracer", "/usr/share/bcc/tools/tcptracer", &params, ""),
}

func init() {
	SnoopCmd.AddCommand(tcptracerCmd)
	utils.AddCommonFlags(tcptracerCmd, &params)
}
