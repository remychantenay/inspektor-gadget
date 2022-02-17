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

package advisor

import (
	"errors"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"

	"github.com/spf13/cobra"
)

// All the gadgets within this package use this global variable, so let's
// declare it here.
var params utils.CommonFlags

var AdvisorCmd = &cobra.Command{
	Use:   "advisor",
	Short: "Recommend system configurations based on collected information",
	RunE: func(cmd *cobra.Command, args []string) error {
		return errors.New("You should not call this without any sub-command.")
	},
}
