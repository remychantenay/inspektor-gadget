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
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/opencontainers/runc/libcontainer/configs"
	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

var (
	verbose      = flag.Bool("verbose", false, "verbose")
	hookPreStart = flag.Bool("hook-prestart", false, "hook PreStart")
	hookPostStop = flag.Bool("hook-poststop", false, "hook PostStop")
	cmd          = flag.String("cmd", "", "the command")
	env          = flag.String("env", "", "the environ")
	dir          = flag.String("dir", "", "dir")
	timeout      = flag.String("timeout", "10s", "timeout")
)

func callback(notif runcfanotify.ContainerEvent) {
	if *verbose {
		if notif.Type == runcfanotify.EVENT_TYPE_ADD_CONTAINER {
			fmt.Printf("Container added: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
			if notif.ContainerConfig != nil && notif.ContainerConfig.Process != nil {
				fmt.Printf("  Command: %s\n", strings.Join(notif.ContainerConfig.Process.Args, " "))
			}
		} else {
			fmt.Printf("Container removed: %v pid %d\n", notif.ContainerID, notif.ContainerPID)
		}
	}

	ociState := &ocispec.State{
		Version: ocispec.Version,
		ID:      notif.ContainerID,
		Pid:     int(notif.ContainerPID),
		Bundle:  "",
	}
	if notif.ContainerConfig != nil && notif.ContainerConfig.Annotations != nil {
		ociState.Annotations = notif.ContainerConfig.Annotations
	} else {
		ociState.Annotations = make(map[string]string)
	}

	match := false
	if notif.Type == runcfanotify.EVENT_TYPE_ADD_CONTAINER && *hookPreStart {
		ociState.Status = ocispec.StateCreated
		match = true
	} else if notif.Type == runcfanotify.EVENT_TYPE_REMOVE_CONTAINER && *hookPostStop {
		ociState.Status = ocispec.StateStopped
		match = true
	}

	if match {
		t, _ := time.ParseDuration(*timeout)
		command := &configs.Command{
			Path:    "/bin/sh",
			Args:    []string{"/bin/sh", "-c", *cmd},
			Env:     strings.Split(*env, " "),
			Dir:     *dir,
			Timeout: &t,
		}

		err := command.Run(ociState)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}
	}
}

func main() {
	flag.Parse()

	supported := runcfanotify.Supported()
	if !supported {
		fmt.Printf("runcfanotify not supported\n")
		os.Exit(1)
	}

	notifier, err := runcfanotify.NewRuncNotifier(callback)
	if err != nil {
		fmt.Printf("runcfanotify failed: %v\n", err)
		os.Exit(1)
	}
	select {}
	runtime.KeepAlive(notifier)
}
