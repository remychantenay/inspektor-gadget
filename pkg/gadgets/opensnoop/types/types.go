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

package types

import (
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	MountNsID uint64 `json:"mountnsid,omitempty"`
	Pid       uint32 `json:"pid,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	Comm      string `json:"pcomm,omitempty"`
	Fd        int    `json:"fd,omitempty"`
	Ret       int    `json:"ret,omitempty"`
	Err       int    `json:"err,omitempty"`
	Path      string `json:"path,omitempty"`
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}
