// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2022 The Inspektor Gadget authors

package standard

import (
	"encoding/json"
	"fmt"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

type Tracer struct {
	gadgets.StandardTracerBase

	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string
}

func NewTracer(config *tracer.Config, resolver containercollection.ContainerResolver, eventCallback func(types.Event), node string) (*Tracer, error) {
	lineCallback := func(line string) {
		event := types.Event{}
		event.Type = eventtypes.NORMAL

		if err := json.Unmarshal([]byte(line), &event); err != nil {
			msg := fmt.Sprintf("failed to unmarshal event: %s", err)
			eventCallback(types.Base(eventtypes.Warn(msg, node)))
			return
		}

		eventCallback(event)
	}

	baseTracer, err := gadgets.NewStandardTracer(lineCallback,
		"/usr/share/bcc/tools/bindsnoop",
		"--json", "--mntnsmap", config.MountnsMap,
		"--containersmap", "/sys/fs/bpf/gadget/containers")
	if err != nil {
		return nil, err
	}

	return &Tracer{
		StandardTracerBase: *baseTracer,
		eventCallback:      eventCallback,
		resolver:           resolver, // not used right now but could be useful in the future
		node:               node,
	}, nil
}

func (t *Tracer) Stop() {
	if err := t.StandardTracerBase.Stop(); err != nil {
		t.eventCallback(types.Base(eventtypes.Warn(err.Error(), t.node)))
	}
}
