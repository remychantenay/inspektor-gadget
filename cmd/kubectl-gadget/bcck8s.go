// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/bcck8s"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
)

var (
	stackFlag  bool
	uniqueFlag bool

	profileKernel bool
	profileUser   bool
)

// create the commands for the different gadgets. The gadgets that have CO-RE
// support should use "/bin/gadgets/" as the path for the binary. Otherwise
// "/usr/share/bcc/tools/" should be used.

var biotopCmd = &cobra.Command{
	Use:   "biotop",
	Short: "Trace block device I/O",
	Run:   bcck8s.BccCmd("biotop", "/usr/share/bcc/tools/biotop", &params, ""),
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Profile CPU usage by sampling stack traces",
	Run:   func() func(*cobra.Command, []string) {
		specificFlag := "-f -d "

		if profileUser {
			specificFlag += "-U "
		} else if profileKernel {
			specificFlag += "-K "
		}

		return bcck8s.BccCmd("profile", "/usr/share/bcc/tools/profile", &params, specificFlag)
	}(),
}

var tcptopCmd = &cobra.Command{
	Use:   "tcptop",
	Short: "Show the TCP traffic in a pod",
	Run:   bcck8s.BccCmd("tcptop", "/usr/share/bcc/tools/tcptop", &params, ""),
}

func init() {
	commands := []*cobra.Command{
		biotopCmd,
		profileCmd,
		tcptopCmd,
	}

	// Add flags for all BCC gadgets
	for _, command := range commands {
		rootCmd.AddCommand(command)
		utils.AddCommonFlags(command, &params)
	}

	// Add flags specific to some BCC gadgets
	profileCmd.PersistentFlags().BoolVarP(
		&profileUser,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	profileCmd.PersistentFlags().BoolVarP(
		&profileKernel,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)
}
