module github.com/kinvolk/inspektor-gadget

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/cilium/ebpf v0.6.3-0.20210910140648-4d5607ee1690
	github.com/containerd/nri v0.1.1-0.20210619071632-28f76457b672
	github.com/containers/common v0.46.0
	github.com/docker/docker v20.10.8+incompatible
	github.com/docker/go-units v0.4.0
	github.com/giantswarm/crd-docs-generator v0.7.1
	github.com/iovisor/gobpf v0.2.0 // indirect
	github.com/kinvolk/traceloop v0.0.0-20210623155108-6f4efc6fca46
	github.com/kr/pretty v0.2.1
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.16.0
	github.com/opencontainers/runtime-spec v1.0.3-0.20210326190908-1c3f411f0417
	github.com/s3rj1k/go-fanotify/fanotify v0.0.0-20201224085348-500f21fac20a
	github.com/seccomp/libseccomp-golang v0.9.2-0.20200616122406-847368b35ebf
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/syndtr/gocapability v0.0.0-20200815063812-42c35b437635
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f
	github.com/weaveworks/tcptracer-bpf v0.0.0-20200114145059-84a08fc667c0
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	google.golang.org/grpc v1.42.0
	google.golang.org/protobuf v1.27.1
	k8s.io/api v0.22.3
	k8s.io/apiextensions-apiserver v0.22.3
	k8s.io/apimachinery v0.22.3
	k8s.io/cli-runtime v0.21.0
	k8s.io/client-go v0.22.3
	k8s.io/code-generator v0.22.3
	k8s.io/cri-api v0.20.6
	sigs.k8s.io/controller-runtime v0.10.3
	sigs.k8s.io/security-profiles-operator v0.3.1-0.20211122222133-6e12fe5f2daa
	sigs.k8s.io/yaml v1.2.0
)

go 1.16
