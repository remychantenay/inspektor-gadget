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
	"testing"
	"time"
)

var integration = flag.Bool("integration", false, "run integration tests")

// image such as docker.io/kinvolk/gadget:latest
var image = flag.String("image", "", "gadget container image")

var githubCI = flag.Bool("github-ci", false, "skip some tests which cannot be run on GitHub CI due to host kernel not BPF ready")

func runCommands(cmds []*command, t *testing.T) {
	// defer all cleanup commands so we are sure to exit clean whatever
	// happened
	defer func() {
		for _, cmd := range cmds {
			if cmd.cleanup {
				cmd.run(t)
			}
		}
	}()

	// defer stopping commands
	defer func() {
		for _, cmd := range cmds {
			if cmd.startAndStop && cmd.started {
				// Wait a bit before stopping the command.
				time.Sleep(10 * time.Second)
				cmd.stop(t)
			}
		}
	}()

	// run all commands but cleanup ones
	for _, cmd := range cmds {
		if cmd.cleanup {
			continue
		}

		cmd.run(t)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*integration {
		fmt.Println("Skipping integration test.")

		os.Exit(0)
	}

	if os.Getenv("KUBECTL_GADGET") == "" {
		fmt.Fprintf(os.Stderr, "please set $KUBECTL_GADGET.")

		os.Exit(-1)
	}

	if *image != "" {
		os.Setenv("GADGET_IMAGE_FLAG", "--image "+*image)
	}

	initCommands := []*command{
		deployInspektorGadget,
		waitUntilInspektorGadgetPodsDeployed,
		waitUntilInspektorGadgetPodsInitialized,
	}

	cleanup := func() {
		fmt.Printf("Clean inspektor-gadget:\n")
		cleanupInspektorGadget.runWithoutTest()
	}

	// defer the cleanup to be sure it's called if the test
	// fails (hence calling runtime.Goexit())
	defer cleanup()

	fmt.Printf("Setup inspektor-gadget:\n")
	for _, cmd := range initCommands {
		err := cmd.runWithoutTest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			cleanup()
			os.Exit(-1)
		}
	}

	ret := m.Run()

	// os.Exit() doesn't call deferred functions, hence do the cleanup manually.
	cleanup()

	os.Exit(ret)
}

func TestBindsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-bindsnoop")

	t.Parallel()

	bindsnoopCmd := &command{
		name:           "Start bindsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop bind -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+nc`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		bindsnoopCmd,
		{
			name:           "Run pod which calls bind()",
			cmd:            busyboxPodCommand(ns, "while true; do nc -l -p 9090 -w 1; done"),
			expectedString: "pod/test-pod created\n",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestBiolatency(t *testing.T) {
	commands := []*command{
		{
			name:           "Run biolatency gadget",
			cmd:            "id=$($KUBECTL_GADGET biolatency start --node $(kubectl get node --no-headers | cut -d' ' -f1)); sleep 15; $KUBECTL_GADGET biolatency stop $id",
			expectedRegexp: `usecs\s+:\s+count\s+distribution`,
		},
	}

	runCommands(commands, t)
}

func TestBiotop(t *testing.T) {
	biotopCmd := &command{
		name:           "Start biotop gadget",
		cmd:            "$KUBECTL_GADGET biotop --node $(kubectl get node --no-headers | cut -d' ' -f1)",
		expectedRegexp: `kube-system\s+etcd[\w-]+\s+etcd\s+\d+\s+etcd`,
		startAndStop:   true,
	}

	commands := []*command{
		biotopCmd,
		{
			name: "Wait a bit.",
			cmd:  "sleep 10",
		},
	}

	runCommands(commands, t)
}

func TestCapabilities(t *testing.T) {
	ns := generateTestNamespaceName("test-capabilities")

	t.Parallel()

	capabilitiesCmd := &command{
		name:           "Start capabilities gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop capabilities -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod.*nice.*CAP_SYS_NICE`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		capabilitiesCmd,
		{
			name:           "Run pod which fails to run nice",
			cmd:            busyboxPodCommand(ns, "while true; do nice -n -20 echo; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestDns(t *testing.T) {
	ns := generateTestNamespaceName("test-dns")

	t.Parallel()

	dnsCmd := &command{
		name:           "Start dns gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop dns -n %s", ns),
		expectedRegexp: `test-pod\s+OUTGOING\s+A\s+microsoft.com`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		dnsCmd,
		{
			name:           "Run pod which interacts with dns",
			cmd:            fmt.Sprintf("kubectl run --restart=Never --image=praqma/network-multitool -n %s test-pod -- sh -c 'while true; do nslookup microsoft.com; done'", ns),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestExecsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-execsnoop")

	t.Parallel()

	execsnoopCmd := &command{
		name:           "Start execsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop exec -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+date`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		execsnoopCmd,
		{
			name:           "Run pod which does a lot of exec",
			cmd:            busyboxPodCommand(ns, "while true; do date; done"),
			expectedString: "pod/test-pod created\n",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestFiletop(t *testing.T) {
	ns := generateTestNamespaceName("test-filetop")

	t.Parallel()

	filetopCmd := &command{
		name:           "Start filetop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET filetop -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+\S*\s+0\s+\d+\s+0\s+\d+\s+R\s+date`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		filetopCmd,
		{
			name:           "Run pod which does IO",
			cmd:            busyboxPodCommand(ns, "while true; do echo date >> /tmp/date.txt; done"),
			expectedString: "pod/test-pod created\n",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestMountsnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-mountsnoop")

	t.Parallel()

	mountsnoopCmd := &command{
		name:           "Start mountsnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop mount -n %s", ns),
		expectedRegexp: `test-pod\s+test-pod\s+mount.*mount\("/mnt", "/mnt", .*\) = -ENOENT`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		mountsnoopCmd,
		{
			name:           "Run pod which tries to mount a directory",
			cmd:            busyboxPodCommand(ns, "while true; do mount /mnt /mnt; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestNetworkpolicy(t *testing.T) {
	ns := generateTestNamespaceName("test-networkpolicy")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name:           "Run test pod",
			cmd:            busyboxPodCommand(ns, "while true; do wget -q -O /dev/null https://kinvolk.io; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run network-policy gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET network-policy monitor -n %s --output ./networktrace.log & sleep 15; kill $!; head networktrace.log", ns),
			expectedRegexp: fmt.Sprintf(`"type":"connect".*"%s".*"test-pod"`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOomkill(t *testing.T) {
	ns := generateTestNamespaceName("test-oomkill")

	t.Parallel()

	oomkillCmd := &command{
		name:           "Start oomkill gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop oomkill -n %s", ns),
		expectedRegexp: `\d+\s+tail`,
		startAndStop:   true,
	}

	limitPodYaml := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: %s
spec:
  containers:
  - name: test-pod-container
    image: busybox
    resources:
      limits:
        memory: "128Mi"
    command: ["/bin/sh", "-c"]
    args:
    - while true; do tail /dev/zero; done
`, ns)

	commands := []*command{
		createTestNamespaceCommand(ns),
		oomkillCmd,
		{
			name:           "Run pod which exhaust memory with memory limits",
			cmd:            fmt.Sprintf("echo '%s' | kubectl apply -f -", limitPodYaml),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestOpensnoop(t *testing.T) {
	ns := generateTestNamespaceName("test-opensnoop")

	t.Parallel()

	opensnoopCmd := &command{
		name:           "Start opensnoop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop open -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+whoami\s+3`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		opensnoopCmd,
		{
			name:           "Run pod which calls open()",
			cmd:            busyboxPodCommand(ns, "while true; do whoami; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProcessCollector(t *testing.T) {
	ns := generateTestNamespaceName("test-process-collector")

	t.Parallel()

	if *githubCI {
		t.Skip("Cannot run process-collector within GitHub CI.")
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name:           "Run nginx pod",
			cmd:            fmt.Sprintf("kubectl run --restart=Never --image=nginx -n %s test-pod", ns),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run process-collector gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET process-collector -n %s", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+nginx\s+\d+`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestProfile(t *testing.T) {
	ns := generateTestNamespaceName("test-profile")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name:           "Run test pod",
			cmd:            busyboxPodCommand(ns, "while true; do echo foo > /dev/null; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run profile gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET profile -n %s -p test-pod -K & sleep 15; kill $!", ns),
			expectedRegexp: `sh;\w+;\w+;\w+open`, // echo is builtin.
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSeccompadvisor(t *testing.T) {
	ns := generateTestNamespaceName("test-seccomp-advisor")

	t.Parallel()

	if *githubCI {
		t.Skip("seccomp-advisor timed out within GitHub CI.")
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name:           "Run test pod",
			cmd:            busyboxPodCommand(ns, "while true; do echo foo; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run seccomp-advisor gadget",
			cmd:            fmt.Sprintf("id=$($KUBECTL_GADGET seccomp-advisor start -n %s -p test-pod); sleep 30; $KUBECTL_GADGET seccomp-advisor stop $id", ns),
			expectedRegexp: `write`,
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestSocketCollector(t *testing.T) {
	ns := generateTestNamespaceName("test-socket-collector")

	t.Parallel()

	if *githubCI {
		t.Skip("Cannot run socket-collector within GitHub CI.")
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name:           "Run nginx pod",
			cmd:            fmt.Sprintf("kubectl run --restart=Never --image=nginx -n %s test-pod", ns),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		{
			name:           "Run socket-collector gadget",
			cmd:            fmt.Sprintf("$KUBECTL_GADGET socket-collector -n %s", ns),
			expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+TCP\s+0\.0\.0\.0`, ns),
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcpconnect(t *testing.T) {
	ns := generateTestNamespaceName("test-tcpconnect")

	t.Parallel()

	tcpconnectCmd := &command{
		name:           "Start tcpconnect gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET snoop tcpconnect -n %s", ns),
		expectedRegexp: fmt.Sprintf(`%s\s+test-pod\s+test-pod\s+\d+\s+wget`, ns),
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcpconnectCmd,
		{
			name:           "Run pod which opens TCP socket",
			cmd:            busyboxPodCommand(ns, "while true; do wget -q -O /dev/null -T 3 http://1.1.1.1; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTcptop(t *testing.T) {
	ns := generateTestNamespaceName("test-tcptop")

	t.Parallel()

	tcptopCmd := &command{
		name:           "Start tcptop gadget",
		cmd:            fmt.Sprintf("$KUBECTL_GADGET tcptop --node $(kubectl get node --no-headers | cut -d' ' -f1) -n %s -p test-pod", ns),
		expectedRegexp: `wget`,
		startAndStop:   true,
	}

	commands := []*command{
		createTestNamespaceCommand(ns),
		tcptopCmd,
		{
			name:           "Run pod which opens TCP socket",
			cmd:            busyboxPodCommand(ns, "while true; do wget -q -O /dev/null https://kinvolk.io; done"),
			expectedRegexp: "pod/test-pod created",
		},
		waitUntilTestPodReadyCommand(ns),
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}

func TestTraceloop(t *testing.T) {
	ns := generateTestNamespaceName("test-traceloop")

	t.Parallel()

	commands := []*command{
		createTestNamespaceCommand(ns),
		{
			name: "Start the traceloop gadget",
			cmd:  "$KUBECTL_GADGET traceloop start",
		},
		{
			name: "Wait traceloop to be started",
			cmd:  "sleep 15",
		},
		{
			name: "Run multiplication pod",
			cmd:  fmt.Sprintf("kubectl run --restart=Never -n %s --image=busybox multiplication -- sh -c 'RANDOM=output ; echo \"3*7*2\" | bc > /tmp/file-$RANDOM ; sleep infinity'", ns),
		},
		{
			name: "Wait until multiplication pod is ready",
			cmd:  fmt.Sprintf("sleep 5 ; kubectl wait -n %s --for=condition=ready pod/multiplication ; kubectl get pod -n %s ; sleep 2", ns, ns),
		},
		{
			name:           "Check traceloop list",
			cmd:            fmt.Sprintf("sleep 20 ; $KUBECTL_GADGET traceloop list -n %s --no-headers | grep multiplication | awk '{print $1\" \"$6}'", ns),
			expectedString: "multiplication started\n",
		},
		{
			name:           "Check traceloop show",
			cmd:            fmt.Sprintf(`TRACE_ID=$($KUBECTL_GADGET traceloop list -n %s --no-headers | `, ns) + `grep multiplication | awk '{printf "%s", $4}') ; $KUBECTL_GADGET traceloop show $TRACE_ID | grep -C 5 write`,
			expectedRegexp: "\\[bc\\] write\\(1, \"42\\\\n\", 3\\)",
		},
		{
			name:    "traceloop list",
			cmd:     "$KUBECTL_GADGET traceloop list -A",
			cleanup: true,
		},
		{
			name:           "Stop the traceloop gadget",
			cmd:            "$KUBECTL_GADGET traceloop stop",
			expectedString: "",
			cleanup:        true,
		},
		{
			name:    "Wait until traceloop is stopped",
			cmd:     "sleep 15",
			cleanup: true,
		},
		deleteTestNamespaceCommand(ns),
	}

	runCommands(commands, t)
}
