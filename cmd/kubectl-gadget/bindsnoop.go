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
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

var bindsnoopCmd = &cobra.Command{
	Use:   "bindsnoop",
	Short: "Trace new processes",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomBindsnoopColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-16s %-6s %-16s %-6s %-16s %-6s %-6s %s\n",
				"NODE", "NAMESPACE", "POD", "CONTAINER",
				"PID", "COMM", "PROT", "ADDR", "PORT", "OPTS", "IF")
		}

		config := &utils.TraceConfig{
			GadgetName:       "bindsnoop",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, bindsnoopTransformLine)
		if err != nil {
			return fmt.Errorf("failed to run tracer: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(bindsnoopCmd)
	utils.AddCommonFlags(bindsnoopCmd, &params)
}

// bindsnoopTransformLine is called to transform an event to columns
// format according to the parameters
func bindsnoopTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "error unmarshalling json: %s", err)
		return ""
	}

	if e.Type == eventtypes.ERR || e.Type == eventtypes.WARN ||
		e.Type == eventtypes.DEBUG || e.Type == eventtypes.INFO {
		fmt.Fprintf(os.Stderr, "%s: node %s: %s", e.Type, e.Node, e.Message)
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		return ""
	}
	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-16s %-6d %-16s %-6s %-16s %-6d %-6s %-6d",
			e.Node, e.Namespace, e.Pod, e.Container,
			e.Pid, e.Comm, e.Protocol, e.Addr, e.Port, e.Options, e.Interface))
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%-16s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%-16s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%-16s", e.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%-16s", e.Container))
			case "pid":
				sb.WriteString(fmt.Sprintf("%-6d", e.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%-16s", e.Comm))
			case "proto":
				sb.WriteString(fmt.Sprintf("%-6s", e.Protocol))
			case "addr":
				sb.WriteString(fmt.Sprintf("%-16s", e.Addr))
			case "port":
				sb.WriteString(fmt.Sprintf("%-6d", e.Port))
			case "opts":
				sb.WriteString(fmt.Sprintf("%-6s", e.Options))
			case "if":
				sb.WriteString(fmt.Sprintf("%-6d", e.Interface))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomBindsnoopColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", "CONTAINER"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-6s", "PID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "proto":
			sb.WriteString(fmt.Sprintf("%-6s", "PROT"))
		case "addr":
			sb.WriteString(fmt.Sprintf("%-16s", "ADDR"))
		case "port":
			sb.WriteString(fmt.Sprintf("%-6s", "PORT"))
		case "opts":
			sb.WriteString(fmt.Sprintf("%-6s", "OPTS"))
		case "if":
			sb.WriteString(fmt.Sprintf("%-6s", "IF"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
