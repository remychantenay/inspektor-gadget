---
# Code generated by 'make generate-documentation'. DO NOT EDIT.
title: Gadget network-policy-advisor
---

The network-policy gadget monitor the network activity in order to generate Kubernetes network policies.

### Example CR

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: network-policy-advisor
  namespace: gadget
spec:
  node: minikube
  gadget: network-policy-advisor
  filter:
    namespace: default
    labels:
      role: demo
  runMode: Manual
  outputMode: Status
```

### Operations


#### start

Start network-policy

```bash
$ kubectl annotate -n gadget trace/network-policy-advisor \
    gadget.kinvolk.io/operation=start
```
#### update

Update results in Trace.Status.Output

```bash
$ kubectl annotate -n gadget trace/network-policy-advisor \
    gadget.kinvolk.io/operation=update
```
#### report

Convert results into network policies

```bash
$ kubectl annotate -n gadget trace/network-policy-advisor \
    gadget.kinvolk.io/operation=report
```
#### stop

Stop network-policy

```bash
$ kubectl annotate -n gadget trace/network-policy-advisor \
    gadget.kinvolk.io/operation=stop
```

### Output Modes

* Status
