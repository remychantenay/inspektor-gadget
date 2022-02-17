// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2022 The Inspektor Gadget authors

package types

import (
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Pid       uint32 `json:"pid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Protocol  string `json:"proto,omitempty"`
	Addr      string `json:"addr,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	Options   string `json:"opts,omitempty"`
	Interface int    `json:"if,omitempty"`
	MountNsId uint64 `json:"mountnsid,omitempty"`
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}
