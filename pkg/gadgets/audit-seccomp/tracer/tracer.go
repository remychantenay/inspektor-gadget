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

package tracer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

// #include <linux/types.h>
// #include "./bpf/audit-seccomp.h"
import "C"

const (
	BPF_PROG_NAME = "kprobe__audit_seccomp"
	BPF_MAP_NAME  = "events"
)

type Tracer struct {
	config        *Config
	eventCallback func(types.Event)
	node          string

	collection *ebpf.Collection
	eventMap   *ebpf.Map
	reader     *perf.Reader

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
}

type Config struct {
	// TODO: Make it a *ebpf.Map once
	// https://github.com/cilium/ebpf/issues/515 and
	// https://github.com/cilium/ebpf/issues/517 are fixed
	ContainersMap string
	MountnsMap    string
}

func NewTracer(config *Config, eventCallback func(types.Event), node string) (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %s", err)
	}

	if config.MountnsMap != "" {
		if filepath.Dir(config.MountnsMap) != gadgets.PIN_PATH {
			return nil, fmt.Errorf("error while checking pin path: only paths in %s are supported", gadgets.PIN_PATH)
		}
		spec.Maps["filter"].Name = filepath.Base(config.MountnsMap)
		spec.Maps["filter"].Pinning = ebpf.PinByName
	}
	if config.ContainersMap != "" {
		if filepath.Dir(config.ContainersMap) != gadgets.PIN_PATH {
			return nil, fmt.Errorf("error while checking pin path: only paths in %s are supported", gadgets.PIN_PATH)
		}
		spec.Maps["containers"].Name = filepath.Base(config.ContainersMap)
		spec.Maps["containers"].Pinning = ebpf.PinByName
	}
	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: gadgets.PIN_PATH,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %s", err)
	}

	rd, err := perf.NewReader(coll.Maps[BPF_MAP_NAME], os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t := &Tracer{
		config:        config,
		eventCallback: eventCallback,
		node:          node,

		collection: coll,
		eventMap:   coll.Maps[BPF_MAP_NAME],
		reader:     rd,
	}

	kprobeProg, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPF_PROG_NAME)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", kprobeProg)
	if err != nil {
		return nil, fmt.Errorf("failed to attach kprobe: %s", err)
	}

	go t.run(rd)

	return t, nil
}

func (t *Tracer) run(rd *perf.Reader) {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg, t.node)))
			continue
		}

		eventC := (*C.struct_event)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
				Pod:  C.GoString(&eventC.pod[0]),
			},
			Pid:       uint32(eventC.pid),
			MountNsId: uint64(eventC.mntns_id),
			Syscall:   syscallToName(int(eventC.syscall)),
			Code:      codeToName(uint(eventC.code)),
			Comm:      C.GoString(&eventC.comm[0]),
		}

		t.eventCallback(event)
	}

}

func (t *Tracer) Close() {
	t.reader.Close()
	t.progLink.Close()
	t.collection.Close()
}
