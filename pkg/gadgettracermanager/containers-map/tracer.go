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

package containersmap

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	BPFMapName = "containers"
)

func CreateContainersMap(pinPath string) (*ebpf.Map, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinPath},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}
	return coll.Maps[BPFMapName], nil
}
