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

package k8s

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils/containerd"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils/crio"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containerutils/docker"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	criClient     containerutils.CRIClient
}

func NewK8sClient(nodeName string) (*K8sClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %w", err)
	}

	// get a CRI client to talk to the CRI handling pods in this node
	// TODO: when to close it?
	criClient, err := newCRIClient(node)
	if err != nil {
		return nil, err
	}

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		criClient:     criClient,
	}, nil
}

func newCRIClient(node *v1.Node) (containerutils.CRIClient, error) {
	criVersion := node.Status.NodeInfo.ContainerRuntimeVersion
	list := strings.Split(criVersion, "://")
	if len(list) < 1 {
		return nil, fmt.Errorf("impossible to get CRI type from %s", criVersion)
	}

	criType := list[0]

	switch criType {
	case "docker":
		return docker.NewDockerClient(docker.DefaultSocketPath)
	case "containerd":
		return containerd.NewContainerdClient(containerd.DefaultSocketPath)
	case "cri-o":
		return crio.NewCrioClient(crio.DefaultSocketPath)
	default:
		return nil, fmt.Errorf("unknown '%s' cri", criType)
	}
}

func (k *K8sClient) CloseCRI() {
	k.criClient.Close()
}

// GetNonRunningContainers returns the list of containers IDs that are not running
func (k *K8sClient) GetNonRunningContainers(pod *v1.Pod) []string {
	ret := []string{}
	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID != "" && s.State.Running == nil {
			ret = append(ret, s.ContainerID)
		}
	}

	return ret
}

// PodToContainers return a list of the containers of a given Pod.
// Containers that are not running or don't have an ID are not considered.
func (k *K8sClient) PodToContainers(pod *v1.Pod) []pb.ContainerDefinition {
	containers := []pb.ContainerDefinition{}

	labels := []*pb.Label{}
	for k, v := range pod.ObjectMeta.Labels {
		labels = append(labels, &pb.Label{Key: k, Value: v})
	}

	for _, s := range pod.Status.ContainerStatuses {
		if s.ContainerID == "" {
			continue
		}
		if s.State.Running == nil {
			continue
		}

		pid, err := k.criClient.PidFromContainerID(s.ContainerID)
		if err != nil {
			log.Warnf("Skip pod %s/%s: cannot find pid: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}
		if pid == 0 {
			log.Warnf("Skip pod %s/%s: got zero pid", pod.GetNamespace(), pod.GetName())
			continue
		}

		idParts := strings.SplitN(s.ContainerID, "//", 2)
		if len(idParts) != 2 {
			continue
		}

		containerDef := pb.ContainerDefinition{
			Id:        idParts[1],
			Namespace: pod.GetNamespace(),
			Podname:   pod.GetName(),
			Name:      s.Name,
			Labels:    labels,
			Pid:       uint32(pid),
		}
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *K8sClient) ListContainers() (arr []pb.ContainerDefinition, err error) {
	// List pods
	pods, err := k.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		containers := k.PodToContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}
