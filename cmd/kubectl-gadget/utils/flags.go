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

package utils

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var KubernetesConfigFlags = genericclioptions.NewConfigFlags(false)

func FlagInit(rootCmd *cobra.Command) {
	cobra.OnInitialize(cobraInit)
	KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func cobraInit() {
	viper.AutomaticEnv()
}

const (
	OutputModeColumns       = "columns"
	OutputModeJson          = "json"
	OutputModeCustomColumns = "custom-columns"
)

var supportedOutputModes = []string{OutputModeColumns, OutputModeJson, OutputModeCustomColumns}

// CommonFlags contains CLI flags common to several gadgets
type CommonFlags struct {
	// LabelsRaw allows to filter containers with a label selector in the
	// following format: key1=value1,key2=value2.
	// It's the raw representation as passed by the user.
	LabelsRaw string

	// Labels is a parsed representation of LabelsRaw
	Labels map[string]string

	// Node allows to filter containers by node name
	Node string

	// Namespace allows to filter by Kubernetes namespace. Ignored if
	// AllNamespaces is true
	Namespace string

	// NamespaceOverridden will be true only if the CommonFlags.Namespace
	// field contains the value passed by the user using the '-n' flag
	// and not the default value configured in the kubeconfig file.
	NamespaceOverridden bool

	// AllNamespaces disables the container filtering by namespace
	AllNamespaces bool

	// Podname allows to filter containers by the pod name
	Podname string

	// Containername allows to filter containers by name
	Containername string

	// OutputMode specifies the way output should be printed
	OutputMode string

	// Verbose prints additional information
	Verbose bool

	// List of columns to print (only meaningful when OutputMode is "columns=...")
	CustomColumns []string
}

// GetNamespace returns the namespace specified by '-n' or the default
// namespace configured in the kubeconfig file. It also returns a boolean
// that specifies if the namespace comes from the '-n' flag or not.
func GetNamespace() (string, bool) {
	namespace, overridden, _ := KubernetesConfigFlags.ToRawKubeConfigLoader().Namespace()
	return namespace, overridden
}

func AddCommonFlags(command *cobra.Command, params *CommonFlags) {
	command.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Namespace
		if !params.AllNamespaces {
			params.Namespace, params.NamespaceOverridden = GetNamespace()
		}

		// Labels
		if params.LabelsRaw != "" {
			params.Labels = make(map[string]string)
			pairs := strings.Split(params.LabelsRaw, ",")
			for _, pair := range pairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					return WrapInErrInvalidParam("--selector / -l",
						fmt.Errorf("should be a comma-separated list of key-value pairs (key=value[,key=value,...])"))
				}
				params.Labels[kv[0]] = kv[1]
			}
		}

		// Verify if the node specified in the filter actually exist. This check
		// will be removed when we will support the addition/deletion of nodes.
		if params.Node != "" {
			client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
			if err != nil {
				return WrapInErrSetupK8sClient(err)
			}

			nodes, err := client.CoreV1().Nodes().List(context.TODO(), metaV1.ListOptions{})
			if err != nil {
				return WrapInErrListNodes(err)
			}

			nodeFound := false
			for _, node := range nodes.Items {
				if node.Name == params.Node {
					nodeFound = true
					break
				}
			}

			if !nodeFound {
				return WrapInErrInvalidParam("--node",
					fmt.Errorf("node %q does not exist", params.Node))
			}
		}

		// Output Mode
		switch {
		case params.OutputMode == OutputModeColumns:
			fallthrough
		case params.OutputMode == OutputModeJson:
			return nil
		case strings.HasPrefix(params.OutputMode, OutputModeCustomColumns):
			parts := strings.Split(params.OutputMode, "=")
			if len(parts) != 2 {
				return WrapInErrInvalidParam(OutputModeCustomColumns,
					errors.New("expects a comma separated list of columns to use"))
			}

			cols := strings.Split(strings.ToLower(parts[1]), ",")
			for _, col := range cols {
				if len(col) == 0 {
					return WrapInErrInvalidParam(OutputModeCustomColumns,
						errors.New("column can't be empty"))
				}
			}

			params.CustomColumns = cols
			params.OutputMode = OutputModeCustomColumns
		default:
			return WrapInErrInvalidParam("--output / -o",
				fmt.Errorf("%q is not a valid output format", params.OutputMode))
		}
		return nil
	}

	// do not print usage when there is an error
	command.SilenceUsage = true

	// No 'Namespace' flag because it's added automatically by
	// KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())

	command.PersistentFlags().StringVarP(
		&params.LabelsRaw,
		"selector",
		"l",
		"",
		"Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
	)

	command.PersistentFlags().StringVar(
		&params.Node,
		"node",
		"",
		"Show only data from pods running in that node",
	)

	command.PersistentFlags().StringVarP(
		&params.Podname,
		"podname",
		"p",
		"",
		"Show only data from pods with that name",
	)

	command.PersistentFlags().StringVarP(
		&params.Containername,
		"containername",
		"c",
		"",
		"Show only data from containers with that name",
	)

	command.PersistentFlags().BoolVarP(
		&params.AllNamespaces,
		"all-namespaces",
		"A",
		false,
		"Show data from pods in all namespaces",
	)

	command.PersistentFlags().StringVarP(
		&params.OutputMode,
		"output",
		"o",
		OutputModeColumns,
		fmt.Sprintf("Output format (%s).", strings.Join(supportedOutputModes, ", ")),
	)

	command.PersistentFlags().BoolVarP(
		&params.Verbose,
		"verbose",
		"",
		false,
		"Print additional information",
	)
}
