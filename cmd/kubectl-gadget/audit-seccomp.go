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
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	types "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	FMT_AUDIT_SECCOMP_ALL   = "%-16.16s %-16.16s %-30.30s %s"
	FMT_AUDIT_SECCOMP_SHORT = "%-30.30s %s"
)

var colAuditSeccompLens = map[string]int{
	"syscall": 30,
}

var auditSeccompCmd = &cobra.Command{
	Use:   "audit-seccomp",
	Short: "Trace syscalls that seccomp sent to the audit log",
	Run: func(cmd *cobra.Command, args []string) {
		transform := transformAuditSeccompLine

		switch {
		case params.OutputMode == utils.OutputModeJson: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, colAuditSeccompLens)
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()
		case params.AllNamespaces:
			fmt.Printf(FMT_AUDIT_SECCOMP_ALL+"\n",
				"NODE",
				"NAMESPACE",
				"POD",
				"SYSCALL",
			)
		default:
			fmt.Printf(FMT_AUDIT_SECCOMP_SHORT+"\n",
				"POD",
				"SYSCALL",
			)
		}

		config := &utils.TraceConfig{
			GadgetName:       "audit-seccomp",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)

			os.Exit(1)
		}

	},
}

func init() {
	rootCmd.AddCommand(auditSeccompCmd)
	utils.AddCommonFlags(auditSeccompCmd, &params)
}

func transformAuditSeccompLine(line string) string {
	event := &types.Event{}
	if err := json.Unmarshal([]byte(line), event); err != nil {
		return fmt.Sprintf("error unmarshaling event: %s", err)
	}

	podMsgSuffix := ""
	if event.Namespace != "" && event.Pod != "" {
		podMsgSuffix = ", pod " + event.Namespace + "/" + event.Pod
	}

	if event.Type == eventtypes.ERR {
		return fmt.Sprintf("Error on node %s%s: %s", event.Node, podMsgSuffix, event.Message)
	}
	if event.Type == eventtypes.DEBUG {
		if !params.Verbose {
			return ""
		}
		return fmt.Sprintf("Debug on node %s%s: %s", event.Node, podMsgSuffix, event.Message)
	}
	if params.AllNamespaces {
		return fmt.Sprintf(FMT_AUDIT_SECCOMP_ALL, event.Node, event.Namespace, event.Pod, event.Syscall)
	} else {
		return fmt.Sprintf(FMT_AUDIT_SECCOMP_SHORT, event.Pod, event.Syscall)
	}
}
