// Copyright 2025 The Inspektor Gadget authors
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
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// keep all these values aligned with program.bpf.c and gadget.yaml
const (
	dropListMap         = "drop_list"
	cidrsKey            = "cidrs"
	cidrsParamMaxLength = 2048
	cidrsMaxSize        = 1024
)

type bpfV4LpmKey struct {
	PrefixLen uint32
	Addr      uint32
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	if err := doGadgetStart(); err != nil {
		api.Errorf("gadgetStart failed: %s", err)
		return 1
	}
	return 0
}

func doGadgetStart() error {
	cidrsVal, err := api.GetParamValue(cidrsKey, cidrsMaxSize)
	if err != nil {
		return fmt.Errorf("failed to get param value: %s", err)
	}

	dropListMap, err := api.GetMap(dropListMap)
	if err != nil {
		return fmt.Errorf("failed to get drop_list: %s", err)
	}

	zero := uint32(0)

	cidrs := strings.Split(cidrsVal, ",")

	if len(cidrs) > cidrsMaxSize {
		return fmt.Errorf("too many CIDRs, max %d", cidrsMaxSize)
	}

	for _, cidr := range cidrs {
		api.Infof("processing: %s", cidr)

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}

		ones, _ := network.Mask.Size()

		key := bpfV4LpmKey{
			PrefixLen: uint32(ones),
			Addr:      ip2int(network.IP),
		}

		if err := dropListMap.Put(key, zero); err != nil {
			return err
		}
	}

	return nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func main() {}
