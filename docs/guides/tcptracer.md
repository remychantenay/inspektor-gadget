---
title: 'The "tcptracer" gadget'
weight: 10
---

The `tcptracer` gadget is used to monitor tcp connections.

## How to use it?

First, we need to create one pod with limited amount of memory:

```bash
$ $ kubectl run busybox --image busybox:latest sleep inf
pod/busybox created
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget tcptracer
NODE             NAMESPACE        POD              CONTAINER        KPID   KCOMM            PAGES  TPID             TCOMM
```

Indeed, it is waiting for TCP connection to be established in the `default` namespace (you can use `-A` to monitor all namespaces and then be sure to not miss any event).
So, in *an other terminal*, `exec` a container and run this `wget`:

```bash
$ kubectl exec -ti busybox -- wget https://www.microsoft.com
Connecting to www.microsoft.com (95.101.225.221:443)
wget: note: TLS certificate validation not implemented
wget: server returned error: HTTP/1.1 403 Forbidden
command terminated with exit code 1
```

Go back to *the first terminal* and see:

```bash
NODE             NAMESPACE        POD              CONTAINER        T PID    COMM             IP  SADDR            DADDR            SPORT   DPORT
minikube         <>               <>               <>               C 19981  wget             4   172.17.0.3       95.101.225.221   34434   443
```

The printed lined correspond to TCP connection established with the socket.
Here is the full legend of all the fields:

* `T`: How the TCP connection was established, it can be one of the following values:
	* `C`: The TCP connection was established after a `connect()` system call.
	* `A`: The TCP connection was established after an `accept()` system call.
	* `X`: The TCP connection was closed following the `close()` system call.
	* `U`: The TCP connection was either established or closed following and unknown reasons.
* `PID`: The PID which calls `connect`.
* `COMM`: The command corresponding to the PID.
* `IP`: The IP version (either 4 or 6).
* `SADDR`: The sender IP address.
* `DADDR`: The destination IP address.
* `SPORT`: The sender port.
* `DPORT`: The destination port.

So, the above line should be read like this: "Command `wget`, which has PID 19981, established a TCP connection, using the `connect()` system call, from the IP version 4 IP 172.17.0.3 and port 34434 towards IP 95.101.255.221 and port 433"

Note that, IP 95.101.255.221 corresponds to `microsoft.com` while port 443 is the port generally used for HTTPS.

## Only print some information

You can restrain the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command:

```bash
$ kubectl gadget tcptracer -A -o custom-columns=pid,comm
PID    COMM
28489  wget
```

The following command is the same as default printing:

```bash
$ kubectl gadget tcptracer -A -o custom-columns=node,namespace,container,pod,t,pid,comm,ip,saddr,daddr,sport,dport
NODE             NAMESPACE        CONTAINER        POD              T PID    COMM             IP  SADDR            DADDR            SPORT   DPORT
minikube         <>               <>               <>               C 29246  wget             4   172.17.0.3       23.57.4.240      34918   443
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget tcptracer -o json
{"type":"normal","node":"minikube","namespace":"\u003c\u003e","pod":"\u003c\u003e","container":"\u003c\u003e","pid":29610,"comm":"wget","ipversion":4,"saddr":"172.17.0.3","daddr":"23.57.4.240","sport":35108,"dport":443,"operation":"connect"}
# You can use jq to make the output easier to read:
$ kubectl gadget tcptracer -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "<>",
  "pod": "<>",
  "container": "<>",
  "pid": 29610,
  "comm": "wget",
  "ipversion": 4,
  "saddr": "172.17.0.3",
  "daddr": "23.57.4.240",
  "sport": 35108,
  "dport": 443,
  "operation": "connect"
}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete pod busybox
pod "busybox" deleted
```
