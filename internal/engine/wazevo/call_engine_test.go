package wazevo

import (
	"encoding/binary"
	"reflect"
	"testing"
	"unsafe"

	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func TestCallEngine_init(t *testing.T) {
	c := &callEngine{}
	c.init()
	require.True(t, c.stackTop%16 == 0)
	require.Equal(t, &c.stack[0], c.execCtx.stackBottomPtr)
}

func TestCallEngine_growStack(t *testing.T) {
	t.Run("stack overflow", func(t *testing.T) {
		c := &callEngine{stack: make([]byte, callStackCeiling+1)}
		_, _, err := c.growStack()
		require.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		s := make([]byte, 32)
		for i := range s {
			s[i] = byte(i)
		}
		c := &callEngine{
			stack:    s,
			stackTop: uintptr(unsafe.Pointer(&s[15])),
			execCtx: executionContext{
				stackGrowRequiredSize:    160,
				stackPointerBeforeGoCall: (*uint64)(unsafe.Pointer(&s[10])),
				framePointerBeforeGoCall: uintptr(unsafe.Pointer(&s[14])),
			},
		}
		newSP, newFp, err := c.growStack()
		require.NoError(t, err)
		require.Equal(t, 160+32*2+16, len(c.stack))

		require.True(t, c.stackTop%16 == 0)
		require.Equal(t, &c.stack[0], c.execCtx.stackBottomPtr)

		var view []byte
		{
			//nolint:staticcheck
			sh := (*reflect.SliceHeader)(unsafe.Pointer(&view))
			sh.Data = newSP
			sh.Len = 5
			sh.Cap = 5
		}
		require.Equal(t, []byte{10, 11, 12, 13, 14}, view)
		require.True(t, newSP >= uintptr(unsafe.Pointer(c.execCtx.stackBottomPtr)))
		require.True(t, newSP <= c.stackTop)
		require.Equal(t, newFp-newSP, uintptr(4))
	})
}

func TestCallEngine_requiredInitialStackSize(t *testing.T) {
	c := &callEngine{}
	require.Equal(t, 10240, c.requiredInitialStackSize())
	c.sizeOfParamResultSlice = 10
	require.Equal(t, 10240, c.requiredInitialStackSize())
	c.sizeOfParamResultSlice = 1000
	require.Equal(t, 1000*16+32+16, c.requiredInitialStackSize())
}

func TestCallEngine_collectGarbage(t *testing.T) {
	var store wasm.ExceptionStore
	newExn := func() *wasm.Exception { return store.NewException(nil, nil, nil) }
	onStack, onStackOffWord, inRegister, belowSP, unnamed := newExn(), newExn(), newExn(), newExn(), newExn()

	// fakeStack is a stack whose stack pointer, at index sp, is 16-byte aligned.
	fakeStack := func() (stack []byte, sp int) {
		stack = make([]byte, 256)
		return stack, int((16-uintptr(unsafe.Pointer(&stack[0]))%16)%16) + 64
	}

	c := &callEngine{}
	var sp int
	c.stack, sp = fakeStack()
	c.stackTop = alignedStackTop(c.stack)
	c.execCtx.stackPointerBeforeGoCall = (*uint64)(unsafe.Pointer(&c.stack[sp]))
	binary.LittleEndian.PutUint64(c.stack[sp+8:], uint64(onStack.ID))
	// Where an i64 spilled after an i32 lands.
	binary.LittleEndian.PutUint64(c.stack[sp+20:], uint64(onStackOffWord.ID))
	// Below the stack pointer is no frame's any more.
	binary.LittleEndian.PutUint64(c.stack[sp-16:], uint64(belowSP.ID))
	c.execCtx.savedRegisters[5][0] = uint64(inRegister.ID)

	for _, e := range []*wasm.Exception{onStack, onStackOffWord, inRegister, belowSP, unnamed} {
		c.holdException(e)
	}
	c.collectGarbage()

	require.Equal(t, map[wasm.Reference]*wasm.Exception{
		onStack.ID:        onStack,
		onStackOffWord.ID: onStackOffWord,
		inRegister.ID:     inRegister,
	}, c.heldExceptions)

	// Collecting again reuses the map the last collection replaced, and must not disturb
	// what it keeps.
	c.collectGarbage()
	require.Equal(t, 3, len(c.heldExceptions))
}

func Test_findLandingPad(t *testing.T) {
	tbl := []wazevoapi.ExceptionTableEntry{
		{CallBlockStart: 10, LandingPad: 100},
		{CallBlockStart: 20, LandingPad: 200},
		{CallBlockStart: 30, LandingPad: 300},
	}
	for _, tc := range []struct {
		name  string
		tbl   []wazevoapi.ExceptionTableEntry
		relPC uint32
		pad   uint32
		ok    bool
	}{
		{"empty table", nil, 0, 0, false},
		{"before the first entry", tbl, 9, 0, false},
		{"exactly the first entry", tbl, 10, 100, true},
		{"inside the first entry", tbl, 19, 100, true},
		{"exactly a middle entry", tbl, 20, 200, true},
		{"exactly the last entry", tbl, 30, 300, true},
		{"past the last entry", tbl, 1 << 20, 300, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pad, ok := findLandingPad(tc.tbl, tc.relPC)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.pad, pad)
		})
	}
}
