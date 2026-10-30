// Package bpf embeds the compiled eBPF objects.
package bpf

import (
	_ "embed"
	"encoding/binary"
)

//go:embed typeobfs_bpfel.o
var objEL []byte

//go:embed typeobfs_bpfeb.o
var objEB []byte

// Object returns the object matching the host endianness.
func Object() []byte {
	var probe [2]byte
	binary.NativeEndian.PutUint16(probe[:], 1)
	if probe[0] == 1 {
		return objEL
	}
	return objEB
}
