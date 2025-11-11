package noise

// DEPRECATED: This file is no longer used.
// The implementation has been migrated to pure Go using golang.org/x/crypto
// See noise.go for the current implementation.

import (
	_ "embed"
	"fmt"

	"github.com/wasmerio/wasmer-go/wasmer"
)

//go:embed noise-c.wasm
var wasmBytes []byte

type WASMInstance struct {
	instance *wasmer.Instance
	memory   *wasmer.Memory
}

func NewWASMInstance() (*WASMInstance, error) {
	return nil, fmt.Errorf("WASM implementation is deprecated - use pure Go implementation in noise.go instead")
}

func (w *WASMInstance) CallFunction(name string, params ...interface{}) ([]wasmer.Value, error) {
	return nil, fmt.Errorf("WASM implementation is deprecated")
}

func (w *WASMInstance) WriteBytesToMemory(offset uint32, data []byte) error {
	return fmt.Errorf("WASM implementation is deprecated")
}

func (w *WASMInstance) ReadBytesFromMemory(offset uint32, length uint32) ([]byte, error) {
	return nil, fmt.Errorf("WASM implementation is deprecated")
}

func (w *WASMInstance) Malloc(size uint32) (uint32, error) {
	return 0, fmt.Errorf("WASM implementation is deprecated")
}

func (w *WASMInstance) Free(ptr uint32) error {
	return fmt.Errorf("WASM implementation is deprecated")
}

func (w *WASMInstance) AllocateBytes(data []byte) (uint32, error) {
	return 0, fmt.Errorf("WASM implementation is deprecated")
}