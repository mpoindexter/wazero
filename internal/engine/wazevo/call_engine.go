package wazevo

import (
	"cmp"
	"context"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/expctxkeys"
	"github.com/tetratelabs/wazero/internal/internalapi"
	"github.com/tetratelabs/wazero/internal/wasm"
	"github.com/tetratelabs/wazero/internal/wasmdebug"
	"github.com/tetratelabs/wazero/internal/wasmruntime"
)

type (
	// callEngine implements api.Function.
	callEngine struct {
		internalapi.WazeroOnly
		stack []byte
		// stackTop is the pointer to the *aligned* top of the stack. This must be updated
		// whenever the stack is changed. This is passed to the assembly function
		// at the very beginning of api.Function Call/CallWithStack.
		stackTop uintptr
		// executable is the pointer to the executable code for this function.
		executable         *byte
		preambleExecutable *byte
		// parent is the *moduleEngine from which this callEngine is created.
		parent *moduleEngine
		// indexInModule is the index of the function in the module.
		indexInModule wasm.Index
		// sizeOfParamResultSlice is the size of the parameter/result slice.
		sizeOfParamResultSlice int
		requiredParams         int
		// execCtx holds various information to be read/written by assembly functions.
		execCtx executionContext
		// execCtxPtr holds the pointer to the executionContext which doesn't change after callEngine is created.
		execCtxPtr        uintptr
		numberOfResults   int
		stackIteratorImpl stackIterator
		// heldExceptions is the reference table for exnrefs stored in locals/stack slots.
		//
		// What a global or table slot holds is counted separately, in the engine's
		// wasm.ExceptionStore; an exception is alive while either count is above zero.
		heldExceptions map[wasm.Reference]*exceptionRefs
		// thrown is the raise this call is propagating, and is nil when it is not
		// propagating one. A call that never throws never allocates it.
		thrown *thrownException
		// entrypoint and afterGoFunctionCallEntrypoint are how this call enters compiled
		// code. Which pair they hold depends on whether the module was compiled with
		// ensureTermination: see entrypoints.
		entrypoint                    entrypointFn
		afterGoFunctionCallEntrypoint afterGoFunctionCallEntrypointFn
	}

	// exceptionRefs is an exception and the number of references to it in this call. The table
	// holds it by pointer so that a reference coming or going is one hash lookup and an
	// increment through it, rather than a lookup, a copy out and a store back.
	exceptionRefs struct {
		exn   *wasm.Exception
		count int32
	}

	// thrownException is one raise, from the throw or throw_ref that starts it to the handler
	// that catches it, and lives no longer than that.
	thrownException struct {
		// tag is what was thrown.
		tag *wasm.TagInstance
		// params holds the tag's argument values, which compiled code stores here at the
		// throw.
		params []uint64
		// trace is the wasm return addresses of where the raise started, innermost first.
		// Propagation unwinds by returning, so by the time an exception turns out to be
		// uncaught its frames are gone; this is captured at the raise, while the stack
		// still reaches it.
		trace []uintptr
		// rethrown is the exception a throw_ref re-raised, and nil when this raise is a fresh
		// throw.
		rethrown *wasm.Exception
	}

	// executionContext is the struct to be read/written by assembly functions.
	executionContext struct {
		// exitCode holds the wazevoapi.ExitCode describing the state of the function execution.
		exitCode wazevoapi.ExitCode
		// callerModuleContextPtr holds the moduleContextOpaque for Go function calls.
		callerModuleContextPtr *byte
		// originalFramePointer holds the original frame pointer of the caller of the assembly function.
		originalFramePointer uintptr
		// originalStackPointer holds the original stack pointer of the caller of the assembly function.
		originalStackPointer uintptr
		// goReturnAddress holds the return address to go back to the caller of the assembly function.
		goReturnAddress uintptr
		// stackBottomPtr holds the pointer to the bottom of the stack.
		stackBottomPtr *byte
		// goCallReturnAddress holds the return address to go back to the caller of the Go function.
		goCallReturnAddress *byte
		// stackPointerBeforeGoCall holds the stack pointer before calling a Go function.
		stackPointerBeforeGoCall *uint64
		// stackGrowRequiredSize holds the required size of stack grow.
		stackGrowRequiredSize uintptr
		// memoryGrowTrampolineAddress holds the address of memory grow trampoline function.
		memoryGrowTrampolineAddress *byte
		// stackGrowCallTrampolineAddress holds the address of stack grow trampoline function.
		stackGrowCallTrampolineAddress *byte
		// checkModuleExitCodeTrampolineAddress holds the address of check-module-exit-code function.
		checkModuleExitCodeTrampolineAddress *byte
		// savedRegisters is the opaque spaces for save/restore registers.
		// We want to align 16 bytes for each register, so we use [64][2]uint64.
		savedRegisters [64][2]uint64
		// goFunctionCallCalleeModuleContextOpaque is the pointer to the target Go function's moduleContextOpaque.
		goFunctionCallCalleeModuleContextOpaque uintptr
		// tableGrowTrampolineAddress holds the address of table grow trampoline function.
		tableGrowTrampolineAddress *byte
		// refFuncTrampolineAddress holds the address of ref-func trampoline function.
		refFuncTrampolineAddress *byte
		// memmoveAddress holds the address of memmove function implemented by Go runtime. See memmove.go.
		memmoveAddress uintptr
		// framePointerBeforeGoCall holds the frame pointer before calling a Go function. Note: only used in amd64.
		framePointerBeforeGoCall uintptr
		// memoryWait32TrampolineAddress holds the address of memory_wait32 trampoline function.
		memoryWait32TrampolineAddress *byte
		// memoryWait32TrampolineAddress holds the address of memory_wait64 trampoline function.
		memoryWait64TrampolineAddress *byte
		// memoryNotifyTrampolineAddress holds the address of the memory_notify trampoline function.
		memoryNotifyTrampolineAddress *byte
		// allocExceptionTrampolineAddress holds the address of the allocate-exception
		// trampoline, called when a throw executes to start the raise and return a params
		// buffer sized to the tag.
		allocExceptionTrampolineAddress *byte
		// matchExceptionTrampolineAddress holds the address of the matchException
		// trampoline, called from a try_table dispatch block to match the in-flight
		// exception against that try_table's catch clauses.
		matchExceptionTrampolineAddress *byte
		// propagateExceptionTrampolineAddress holds the address of the propagate-exception
		// trampoline, called from a function's propagate path to overwrite this frame's
		// saved return address with the caller's landing pad, so the frame's ordinary
		// return unwinds the exception one level into the handler (see ExitCodeThrow).
		propagateExceptionTrampolineAddress *byte
		// exnrefSlotLoadTrampolineAddress and exnrefSlotStoreTrampolineAddress hold the
		// addresses of the barriers an exnref-typed global or table slot is accessed
		// through. Compiled code passes the address of the slot and lets the runtime do the
		// access itself, so that it cannot race another barrier on the same slot.
		exnrefSlotLoadTrampolineAddress  *byte
		exnrefSlotStoreTrampolineAddress *byte
		// raiseRefTrampolineAddress holds the address of the throw_ref trampoline, which
		// records the exception guest code is raising as the one in flight. A throw does
		// this in the allocate-exception trampoline instead.
		raiseRefTrampolineAddress *byte
		// exnrefSlotFillTrampolineAddress and exnrefSlotCopyTrampolineAddress hold the
		// addresses of the barriers over a run of exnref-typed table slots, which the bulk
		// table operations write.
		exnrefSlotFillTrampolineAddress *byte
		exnrefSlotCopyTrampolineAddress *byte
		// adjustExnrefsTrampolineAddress holds the address of the trampoline compiled code
		// calls to adjust this call's exnref reference counts.
		adjustExnrefsTrampolineAddress *byte
		// caughtExceptionParams points at the params of the exception a handler was just
		// entered for. matchException sets it; the handler loads the values out of it and
		// nothing reads it after that, so the next match is free to overwrite it.
		//
		// Its purpose is to be a Go pointer: compiled code reads the params through this
		// address, and the field being pointer-typed is what keeps the array from being
		// collected while it does -- a pointer to an object's first word keeps the whole
		// object alive.
		caughtExceptionParams *uint64
		// moduleClosedPtr is a pointer to the underlying uint64 of the
		// owning ModuleInstance.Closed field. Compiled code reads through it
		// at every loop back-edge (when ensureTermination is on) and calls
		// back into Go when non-zero.
		moduleClosedPtr *uint64
	}
)

func (c *callEngine) requiredInitialStackSize() int {
	const initialStackSizeDefault = 10240
	stackSize := initialStackSizeDefault
	paramResultInBytes := c.sizeOfParamResultSlice * 8 * 2 // * 8 because uint64 is 8 bytes, and *2 because we need both separated param/result slots.
	required := paramResultInBytes + 32 + 16               // 32 is enough to accommodate the call frame info, and 16 exists just in case when []byte is not aligned to 16 bytes.
	if required > stackSize {
		stackSize = required
	}
	return stackSize
}

func (c *callEngine) init() {
	stackSize := c.requiredInitialStackSize()
	if wazevoapi.StackGuardCheckEnabled {
		stackSize += wazevoapi.StackGuardCheckGuardPageSize
	}
	c.stack = make([]byte, stackSize)
	c.stackTop = alignedStackTop(c.stack)
	if wazevoapi.StackGuardCheckEnabled {
		c.execCtx.stackBottomPtr = &c.stack[wazevoapi.StackGuardCheckGuardPageSize]
	} else {
		c.execCtx.stackBottomPtr = &c.stack[0]
	}
	c.execCtxPtr = uintptr(unsafe.Pointer(&c.execCtx))
}

// alignedStackTop returns 16-bytes aligned stack top of given stack.
// 16 bytes should be good for all platform (arm64/amd64).
func alignedStackTop(s []byte) uintptr {
	stackAddr := uintptr(unsafe.Pointer(&s[len(s)-1]))
	return stackAddr - (stackAddr & (16 - 1))
}

// Definition implements api.Function.
func (c *callEngine) Definition() api.FunctionDefinition {
	return c.parent.module.Source.FunctionDefinition(c.indexInModule)
}

// Call implements api.Function.
func (c *callEngine) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	if c.requiredParams != len(params) {
		return nil, fmt.Errorf("expected %d params, but passed %d", c.requiredParams, len(params))
	}
	paramResultSlice := make([]uint64, c.sizeOfParamResultSlice)
	copy(paramResultSlice, params)
	if err := c.callWithStack(ctx, paramResultSlice); err != nil {
		return nil, err
	}
	return paramResultSlice[:c.numberOfResults], nil
}

// storeExnrefSlot is the write barrier for an exnref-typed global or table slot. The handle
// comes from guest code, so this call must hold what it names.
func (c *callEngine) storeExnrefSlot(slot *wasm.Reference, handle wasm.Reference) {
	c.storeSlotHoldingOperand(slot, handle)
	c.releaseIfHeld(handle)
}

// storeSlotHoldingOperand is storeExnrefSlot without releasing the operand's reference, for
// the bulk fill: one operand fills many slots, so it is one reference to release once at the
// end rather than per slot.
func (c *callEngine) storeSlotHoldingOperand(slot *wasm.Reference, handle wasm.Reference) {
	var exn *wasm.Exception
	if handle != 0 {
		if exn = c.heldException(handle); exn == nil {
			panic(wasmruntime.ErrRuntimeExpiredExceptionRef)
		}
	}
	c.parent.parent.parent.exceptions.StoreSlot(slot, exn)
}

// loadExnrefSlot is the read barrier: what a slot names becomes reachable from this call,
// so it has to stay resolvable even if the slot is overwritten before the call ends.
func (c *callEngine) loadExnrefSlot(slot *wasm.Reference) wasm.Reference {
	exn := c.parent.parent.parent.exceptions.LoadSlot(slot)
	if exn == nil {
		return 0
	}
	c.holdException(exn)
	return exn.ID
}

// exceptionOf returns the exception naming this raise: the one a throw_ref re-raised, or a new
// one around what a throw left behind.
func (c *callEngine) exceptionOf(t *thrownException) *wasm.Exception {
	if t.rethrown != nil {
		return t.rethrown
	}
	// Only this call can resolve the exnref params: it is the one that had them on its
	// operand stack. Ones it cannot reach are left out -- nothing can reach those, so
	// there is nothing to keep alive.
	var paramRefs []*wasm.Exception
	for i, vt := range t.tag.Type.Params {
		if wasm.IsExnref(vt) {
			if p := c.heldException(wasm.Reference(t.params[i])); p != nil {
				paramRefs = append(paramRefs, p)
			}
		}
	}
	return c.parent.parent.parent.exceptions.NewException(t.tag, t.params, t.trace, paramRefs)
}

// heldException is the exception this call holds under the given handle, and nil when it holds
// none -- which is the same answer for a handle that never named one and for a handle whose
// last reference has gone, because guest code has no way to tell those apart either.
func (c *callEngine) heldException(handle wasm.Reference) *wasm.Exception {
	if e := c.heldExceptions[handle]; e != nil {
		return e.exn
	}
	return nil
}

// holdException records one more reference to exn. Every path by which guest code comes to
// hold an exnref goes through here, which is what makes the count a complete answer rather
// than a lower bound -- a reference the compiler creates without saying so would let the
// count reach zero while guest code still has the handle.
func (c *callEngine) holdException(exn *wasm.Exception) {
	if e := c.heldExceptions[exn.ID]; e != nil {
		e.count++
		return
	}
	if c.heldExceptions == nil {
		c.heldExceptions = make(map[wasm.Reference]*exceptionRefs)
	}
	c.heldExceptions[exn.ID] = &exceptionRefs{exn: exn, count: 1}
}

// releaseIfHeld drops one reference unless the handle is `ref.null exn`, which never had one.
func (c *callEngine) releaseIfHeld(handle wasm.Reference) {
	if handle != 0 {
		c.releaseException(handle)
	}
}

// releaseException drops one reference. The exception stops being resolvable by this call
// once the last one goes, which is what bounds the table to what guest code can still reach.
func (c *callEngine) releaseException(handle wasm.Reference) {
	e := c.heldExceptions[handle]
	if e == nil {
		// A handle with no reference means the compiler emitted a release without a matching
		// hold. Staying quiet here would turn that into a use-after-free somewhere further
		// away, so it is worth failing at the point the accounting first disagrees.
		panic(fmt.Sprintf("BUG: released exnref %#x that this call holds no reference to", handle))
	}
	if e.count--; e.count == 0 {
		delete(c.heldExceptions, handle)
	}
}

// holdParamRefs holds the exceptions named by exn's exnref params, which a tag-matched
// clause is about to push for the handler.
func (c *callEngine) holdParamRefs(exn *wasm.Exception) {
	for _, p := range exn.ParamRefs {
		c.holdException(p)
	}
}

// abortListenerOf notifies the listener of the function containing addr, if it has one,
// that an exception is unwinding its frame. Compiled code calls the after-listener on the
// return paths, which a frame an exception takes out never reaches.
func (c *callEngine) abortListenerOf(ctx context.Context, addr uintptr) {
	// Unwinding runs this per frame, so try the module the call is running in first: a
	// range check rather than a search over everything the engine holds.
	cm := c.parent.parent
	if !checkAddrInBytes(addr, cm.executable) {
		if cm = c.parent.parent.parent.compiledModuleOfAddr(addr); cm == nil {
			return
		}
	}
	if len(cm.listeners) == 0 {
		return
	}
	index := cm.functionIndexOf(addr)
	def := cm.module.FunctionDefinition(cm.module.ImportFunctionCount + index)
	if lsn := cm.listeners[index]; lsn != nil {
		lsn.Abort(ctx, c.callerModuleInstance(), def, experimental.ErrUnwoundByException)
	}
}

func (c *callEngine) addFrame(builder wasmdebug.ErrorBuilder, addr uintptr) (def api.FunctionDefinition, listener experimental.FunctionListener) {
	eng := c.parent.parent.parent
	cm := eng.compiledModuleOfAddr(addr)
	if cm == nil {
		// This case, the module might have been closed and deleted from the engine.
		// We fall back to searching the imported modules that can be referenced from this callEngine.

		// First, we check itself.
		if checkAddrInBytes(addr, c.parent.parent.executable) {
			cm = c.parent.parent
		} else {
			// Otherwise, search all imported modules. TODO: maybe recursive, but not sure it's useful in practice.
			p := c.parent
			for i := range p.importedFunctions {
				candidate := p.importedFunctions[i].me.parent
				if checkAddrInBytes(addr, candidate.executable) {
					cm = candidate
					break
				}
			}
		}
	}

	if cm != nil {
		index := cm.functionIndexOf(addr)
		def = cm.module.FunctionDefinition(cm.module.ImportFunctionCount + index)
		var sources []string
		if dw := cm.module.DWARFLines; dw != nil {
			sourceOffset := cm.getSourceOffset(addr)
			sources = dw.Line(sourceOffset)
		}
		builder.AddFrame(def.DebugName(), def.ParamTypes(), def.ResultTypes(), sources)
		if len(cm.listeners) > 0 {
			listener = cm.listeners[index]
		}
	}
	return
}

// CallWithStack implements api.Function.
func (c *callEngine) CallWithStack(ctx context.Context, paramResultStack []uint64) (err error) {
	if c.sizeOfParamResultSlice > len(paramResultStack) {
		return fmt.Errorf("need %d params, but stack size is %d", c.sizeOfParamResultSlice, len(paramResultStack))
	}
	return c.callWithStack(ctx, paramResultStack)
}

// CallWithStack implements api.Function.
func (c *callEngine) callWithStack(ctx context.Context, paramResultStack []uint64) (err error) {
	snapshotEnabled := ctx.Value(expctxkeys.EnableSnapshotterKey{}) != nil
	if snapshotEnabled {
		ctx = context.WithValue(ctx, expctxkeys.SnapshotterKey{}, c)
	}

	if wazevoapi.StackGuardCheckEnabled {
		defer func() {
			wazevoapi.CheckStackGuardPage(c.stack)
		}()
	}

	p := c.parent
	ensureTermination := p.parent.ensureTermination
	m := p.module
	if ensureTermination {
		select {
		case <-ctx.Done():
			// If the provided context is already done, close the module and return the error.
			m.CloseWithCtxErr(ctx)
			return m.FailIfClosed()
		default:
		}
	}

	// Clear any stale in-flight exception state from a previous call.
	c.thrown = nil
	c.execCtx.caughtExceptionParams = nil
	clear(c.heldExceptions)

	var paramResultPtr *uint64
	if len(paramResultStack) > 0 {
		paramResultPtr = &paramResultStack[0]
	}
	defer func() {
		r := recover()
		if s, ok := r.(*snapshot); ok {
			// A snapshot that wasn't handled was created by a different call engine possibly from a nested wasm invocation,
			// let it propagate up to be handled by the caller.
			panic(s)
		}
		if r != nil {
			type listenerForAbort struct {
				def api.FunctionDefinition
				lsn experimental.FunctionListener
			}

			var listeners []listenerForAbort
			builder := wasmdebug.NewErrorBuilder()
			addFrame := func(addr uintptr) {
				def, lsn := c.addFrame(builder, addr)
				if lsn != nil {
					listeners = append(listeners, listenerForAbort{def, lsn})
				}
			}
			// An uncaught exception, as opposed to a trap, which aborts on the live stack.
			if t := c.thrown; t != nil {
				trace := t.trace
				// Uncaught: it unwound the stack on its way out, so walking it now would
				// read dead frames. Replay what was captured at the raise. These frames get
				// no listener notification: each was aborted as it was unwound.
				for _, retAddr := range trace[:len(trace)-1] {
					c.addFrame(builder, retAddr)
				}
				// Thrown somewhere other than where it was last thrown: say both. These
				// frames are long gone, so they are context, not the stack that aborted.
				// Only an exception carried here by throw_ref has an origin of its own; a
				// fresh throw's is the raise trace itself.
				var origin []uintptr
				if t.rethrown != nil {
					origin, _ = t.rethrown.Origin.([]uintptr)
				}
				if len(origin) > 0 && !slices.Equal(origin, trace) {
					builder.StartSection(wasmdebug.ExceptionOriginSection)
					for _, retAddr := range origin[:len(origin)-1] {
						c.addFrame(builder, retAddr)
					}
				}
			} else if c.execCtx.stackPointerBeforeGoCall != nil {
				addFrame(uintptr(unsafe.Pointer(c.execCtx.goCallReturnAddress)))
				returnAddrs := unwindStack(
					uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)),
					c.execCtx.framePointerBeforeGoCall,
					c.stackTop,
					nil,
				)
				if len(returnAddrs) > 1 {
					for _, retAddr := range returnAddrs[:len(returnAddrs)-1] { // the last return addr is the trampoline, so we skip it.
						addFrame(retAddr)
					}
				}
			}
			err = builder.FromRecovered(r)

			for _, lsn := range listeners {
				lsn.lsn.Abort(ctx, m, lsn.def, err)
			}
		} else {
			if err != wasmruntime.ErrRuntimeStackOverflow { // Stackoverflow case shouldn't be panic (to avoid extreme stack unwinding).
				err = c.parent.module.FailIfClosed()
			}
		}

		if err != nil {
			// Ensures that we can reuse this callEngine even after an error.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
		}
		if err == nil && len(c.heldExceptions) != 0 {
			// By the time a call returns normally, every operand stack slot and local that
			// held a reference should have released it
			n := len(c.heldExceptions)
			clear(c.heldExceptions)
			c.thrown, c.execCtx.caughtExceptionParams = nil, nil
			panic(fmt.Sprintf("BUG: %d exnref reference(s) still held when the call returned", n))
		}
		// Drop this call's pins. What a global or table holds stays alive in the store.
		c.thrown = nil
		c.execCtx.caughtExceptionParams = nil
		clear(c.heldExceptions)
	}()

	if ensureTermination {
		done := m.CloseModuleOnCanceledOrTimeout(ctx)
		defer done()
	}

	if c.stackTop&(16-1) != 0 {
		panic("BUG: stack must be aligned to 16 bytes")
	}
	c.entrypoint(c.preambleExecutable, c.executable, c.execCtxPtr, c.parent.opaquePtr, paramResultPtr, c.stackTop)
	for {
		switch ec := c.execCtx.exitCode; ec & wazevoapi.ExitCodeMask {
		case wazevoapi.ExitCodeOK:
			if c.thrown != nil {
				// The top-level function returned while an exception was still in flight
				// (no enclosing handler matched): it is uncaught. The wasm stack has
				// already been unwound by the propagating returns, so the saved stack
				// pointer now describes dead frames -- clear it so the abort handler
				// cannot walk them, and let it use the raise trace, captured while they were
				// still live.
				//
				// The raise stays set through the panic so the abort handler can still say
				// where the exception came from; the deferred cleanup clears it.
				c.execCtx.stackPointerBeforeGoCall = nil
				panic(wasmruntime.ErrRuntimeUncaughtException)
			}
			return nil
		case wazevoapi.ExitCodeGrowStack:
			oldsp := uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
			oldTop := c.stackTop
			oldStack := c.stack
			var newsp, newfp uintptr
			if wazevoapi.StackGuardCheckEnabled {
				newsp, newfp, err = c.growStackWithGuarded()
			} else {
				newsp, newfp, err = c.growStack()
			}
			if err != nil {
				return err
			}
			adjustClonedStack(oldsp, oldTop, newsp, newfp, c.stackTop)
			// Old stack must be alive until the new stack is adjusted.
			runtime.KeepAlive(oldStack)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr, newsp, newfp)
		case wazevoapi.ExitCodeGrowMemory:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			argRes := &s[0]
			if res, ok := mem.Grow(uint32(*argRes)); !ok {
				*argRes = uint64(0xffffffff) // = -1 in signed 32-bit integer.
			} else {
				*argRes = uint64(res)
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr, uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeTableGrow:
			mod := c.callerModuleInstance()
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			tableIndex, num, ref := uint32(s[0]), uint32(s[1]), uintptr(s[2])
			table := mod.Tables[tableIndex]
			before := uint64(len(table.References))
			s[0] = uint64(uint32(int32(table.Grow(num, ref))))
			if wasm.IsExnref(table.Type) && ref != 0 {
				// Grow wrote the new slots already; record one more naming apiece.
				exn := c.heldException(ref)
				if exn == nil {
					panic(wasmruntime.ErrRuntimeExpiredExceptionRef)
				}
				for i := before; i < uint64(len(table.References)); i++ {
					c.parent.parent.parent.exceptions.Retain(exn)
				}
			}
			if wasm.IsExnref(table.Type) {
				c.releaseIfHeld(ref) // the operand, whether or not the grow succeeded.
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoFunction:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, goCallStackView(c.execCtx.stackPointerBeforeGoCall))
			}()
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoFunctionWithListener:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			listeners := hostModuleListenersSliceFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Call Listener.Before.
			callerModule := c.callerModuleInstance()
			listener := listeners[index]
			hostModule := hostModuleFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			def := hostModule.FunctionDefinition(wasm.Index(index))
			listener.Before(ctx, callerModule, def, s, c.stackIterator(true))
			// Call into the Go function.
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, s)
			}()
			// Call Listener.After.
			listener.After(ctx, callerModule, def, s)
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoModuleFunction:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoModuleFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			mod := c.callerModuleInstance()
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, mod, goCallStackView(c.execCtx.stackPointerBeforeGoCall))
			}()
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoModuleFunctionWithListener:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoModuleFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			listeners := hostModuleListenersSliceFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Call Listener.Before.
			callerModule := c.callerModuleInstance()
			listener := listeners[index]
			hostModule := hostModuleFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			def := hostModule.FunctionDefinition(wasm.Index(index))
			listener.Before(ctx, callerModule, def, s, c.stackIterator(true))
			// Call into the Go function.
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, callerModule, s)
			}()
			// Call Listener.After.
			listener.After(ctx, callerModule, def, s)
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallListenerBefore:
			stack := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			index := wasm.Index(stack[0])
			mod := c.callerModuleInstance()
			listener := mod.Engine.(*moduleEngine).listeners[index]
			def := mod.Source.FunctionDefinition(index + mod.Source.ImportFunctionCount)
			listener.Before(ctx, mod, def, stack[1:], c.stackIterator(false))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallListenerAfter:
			stack := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			index := wasm.Index(stack[0])
			mod := c.callerModuleInstance()
			listener := mod.Engine.(*moduleEngine).listeners[index]
			def := mod.Source.FunctionDefinition(index + mod.Source.ImportFunctionCount)
			listener.After(ctx, mod, def, stack[1:])
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCheckModuleExitCode:
			// Note: this operation must be done in Go, not native code. The reason is that
			// native code cannot be preempted and that means it can block forever if there are not
			// enough OS threads (which we don't have control over).
			if err := m.FailIfClosed(); err != nil {
				panic(err)
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeRefFunc:
			mod := c.callerModuleInstance()
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			funcIndex := wasm.Index(s[0])
			ref := mod.Engine.FunctionInstanceReference(funcIndex)
			s[0] = uint64(ref)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryWait32:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			if !mem.Shared {
				panic(wasmruntime.ErrRuntimeExpectedSharedMemory)
			}

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			timeout, exp, addr := int64(s[0]), uint32(s[1]), uintptr(s[2])
			base := uintptr(unsafe.Pointer(&mem.Buffer[0]))

			offset := uint32(addr - base)
			res := mem.Wait32(offset, exp, timeout, func(mem *wasm.MemoryInstance, offset uint32) uint32 {
				addr := unsafe.Add(unsafe.Pointer(&mem.Buffer[0]), offset)
				return atomic.LoadUint32((*uint32)(addr))
			})
			s[0] = res
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryWait64:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			if !mem.Shared {
				panic(wasmruntime.ErrRuntimeExpectedSharedMemory)
			}

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			timeout, exp, addr := int64(s[0]), uint64(s[1]), uintptr(s[2])
			base := uintptr(unsafe.Pointer(&mem.Buffer[0]))

			offset := uint32(addr - base)
			res := mem.Wait64(offset, exp, timeout, func(mem *wasm.MemoryInstance, offset uint32) uint64 {
				addr := unsafe.Add(unsafe.Pointer(&mem.Buffer[0]), offset)
				return atomic.LoadUint64((*uint64)(addr))
			})
			s[0] = uint64(res)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryNotify:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			count, addr := uint32(s[0]), s[1]
			offset := uint32(uintptr(addr) - uintptr(unsafe.Pointer(&mem.Buffer[0])))
			res := mem.Notify(offset, count)
			s[0] = uint64(res)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeUnreachable:
			panic(wasmruntime.ErrRuntimeUnreachable)
		case wazevoapi.ExitCodeMemoryOutOfBounds:
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		case wazevoapi.ExitCodeTableOutOfBounds:
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		case wazevoapi.ExitCodeIndirectCallNullPointer:
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		case wazevoapi.ExitCodeIndirectCallTypeMismatch:
			panic(wasmruntime.ErrRuntimeIndirectCallTypeMismatch)
		case wazevoapi.ExitCodeIntegerOverflow:
			panic(wasmruntime.ErrRuntimeIntegerOverflow)
		case wazevoapi.ExitCodeIntegerDivisionByZero:
			panic(wasmruntime.ErrRuntimeIntegerDivideByZero)
		case wazevoapi.ExitCodeInvalidConversionToInteger:
			panic(wasmruntime.ErrRuntimeInvalidConversionToInteger)
		case wazevoapi.ExitCodeUnalignedAtomic:
			panic(wasmruntime.ErrRuntimeUnalignedAtomic)
		case wazevoapi.ExitCodeThrowAlloc:
			// Start the raise and return a params buffer sized exactly to the tag, for
			// compiled code to store the params into. No exception object yet: it takes a
			// handler to say whether one is ever needed.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			tagIndex := int(s[0])
			mod := c.callerModuleInstance()
			tag := mod.Tags[tagIndex]
			trace := unwindStack(uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall, c.stackTop, nil)
			t := &thrownException{tag: tag, trace: trace}
			if n := len(tag.Type.Params); n > 0 {
				t.params = make([]uint64, n)
			}
			c.thrown = t
			s[0] = uint64(uintptr(unsafe.Pointer(unsafe.SliceData(t.params))))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMatchException:
			// matchException trampoline: (execCtx, tryTableID) → (clauseIdx, exnref).
			// Reached from a compiled try_table dispatch block while an exception is in
			// flight. Matches the exception the runtime has in flight against
			// the named try_table's catch clauses, using the catching module's tag space,
			// and returns both the matched clause index (which the compiled dispatch block
			// feeds to its br_table) and the exnref (which the matched handler consumes)
			// via the go-call result slots. No stack unwinding happens here: propagation
			// across frames is done by compiled code via normal returns.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			localFnIdx, ordinal := wazevoapi.TryTableIDParts(s[0])
			mod := c.callerModuleInstance()
			me := mod.Engine.(*moduleEngine)
			info := &me.parent.tryTableInfo[localFnIdx][ordinal]
			t := c.thrown
			clauseIdx := int64(-1)
			for i := range info.CatchClauses {
				clause := &info.CatchClauses[i]
				matched := false
				switch clause.Kind {
				case wasm.CatchKindCatch, wasm.CatchKindCatchRef:
					matched = mod.Tags[clause.TagIndex] == t.tag
				case wasm.CatchKindCatchAll, wasm.CatchKindCatchAllRef:
					matched = true
				}
				if matched {
					clauseIdx = int64(i)
					break
				}
			}
			var handle wasm.Reference
			if clauseIdx >= 0 {
				// Caught: build the exception if this clause hands anything to guest code,
				// since what it hands over -- params to read, a handle to throw again --
				// outlives the raise.
				switch info.CatchClauses[clauseIdx].Kind {
				case wasm.CatchKindCatch:
					if len(t.params) > 0 {
						exn := c.exceptionOf(t)
						c.execCtx.caughtExceptionParams = unsafe.SliceData(exn.Params)
						c.holdParamRefs(exn)
					}
				case wasm.CatchKindCatchRef:
					exn := c.exceptionOf(t)
					c.execCtx.caughtExceptionParams = unsafe.SliceData(exn.Params)
					c.holdParamRefs(exn)
					c.holdException(exn)
					handle = exn.ID
				case wasm.CatchKindCatchAllRef:
					exn := c.exceptionOf(t)
					c.holdException(exn)
					handle = exn.ID
				case wasm.CatchKindCatchAll:
					// Hands over nothing, so nothing needs to outlive the raise.
				}
				// This raise is over -- whatever outlives it belongs to the exception by
				// now -- and a later throw_ref is a new one with its own stack.
				if t.rethrown == nil {
					// A fresh throw, so this raise held the references its exnref params
					// name. exceptionOf, if a clause above wanted them, has already put the
					// exceptions they name in ParamRefs, which is what keeps them reachable
					// from here on.
					for i, vt := range t.tag.Type.Params {
						if wasm.IsExnref(vt) {
							c.releaseIfHeld(wasm.Reference(t.params[i]))
						}
					}
				}
				c.thrown = nil
			}
			// Return the matched clause index and the exnref via the go-call result slots.
			// The handle is zero unless the matched clause hands one over; a handler that
			// takes params reads them through execCtx.caughtExceptionParams instead.
			s[0] = uint64(clauseIdx)
			s[1] = uint64(handle)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeThrow:
			// Unwind the in-flight exception one frame: redirect the propagating frame's
			// return into its caller's exception handler. We overwrite the frame's saved
			// return address with the landing-pad PC for the call site it returns to, so
			// its ordinary return lands in the handler instead of the normal continuation.
			sp := uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
			fp := c.execCtx.framePointerBeforeGoCall
			// The frame this runs for leaves without returning, which is what Abort reports.
			// It fires here rather than where the exception comes to rest, since the frame
			// is gone either way.
			c.abortListenerOf(ctx, goCallerReturnAddr(sp, fp))
			retAddr := returnAddrAt(sp, fp) // where the propagating frame returns into its caller.
			eng := c.parent.parent.parent
			if cm := eng.compiledModuleOfAddr(retAddr); cm != nil {
				fnIdx := cm.functionIndexOf(retAddr)
				base := uintptr(unsafe.Pointer(&cm.executable[0])) + uintptr(cm.functionOffsets[fnIdx])
				if rel, ok := findLandingPad(cm.exceptionTables[fnIdx], uint32(retAddr-base)-1); ok {
					setReturnAddrAt(sp, fp, base+uintptr(rel)) // the frame's ret now goes to the handler.
				}
				// else: this call site has no handler because the caller is the entry
				// trampoline — the exception escaped the outermost wasm frame. Leaving the
				// return address makes the frame return to the entry, where the still-
				// pending exception becomes ErrRuntimeUncaughtException.
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr, sp, fp)
		case wazevoapi.ExitCodeRaiseRef:
			// throw_ref trampoline: (execCtx, exnref). Records what guest code is raising
			// as the exception in flight, which every raise does before transferring
			// control -- a throw does it in the allocate-exception trampoline instead.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			exn := c.heldException(wasm.Reference(s[0]))
			if exn == nil {
				// One this call cannot reach, such as a handle host code kept from an
				// earlier call.
				panic(wasmruntime.ErrRuntimeExpiredExceptionRef)
			}
			// This raise starts here, not where the exception was first thrown, which
			// exn.Origin still has.
			trace := unwindStack(uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall, c.stackTop, nil)
			c.thrown = &thrownException{
				tag: exn.Tag, params: exn.Params, rethrown: exn, trace: trace,
			}
			// The raise consumes the operand. The exception stays alive through c.thrown, and
			// a handler that catches it takes a fresh reference.
			c.releaseIfHeld(wasm.Reference(s[0]))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeExnrefSlotFill:
			// (execCtx, slot address, exnref, count): every slot the fill covers becomes a
			// durable holder of what it now names, and stops being one for what it held.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			slots := *(**wasm.Reference)(unsafe.Pointer(&s[0]))
			handle, count := wasm.Reference(s[1]), s[2]
			for i := uint64(0); i < count; i++ {
				c.storeSlotHoldingOperand((*wasm.Reference)(unsafe.Add(unsafe.Pointer(slots), i*8)), handle)
			}
			// One operand, one reference, however many slots it filled.
			c.releaseIfHeld(handle)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeExnrefSlotCopy:
			// (execCtx, destination address, source address, count), for table.copy and
			// table.init. The source is snapshotted first: the runs may overlap, and each
			// write releases what the destination slot held.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			dst := *(**wasm.Reference)(unsafe.Pointer(&s[0]))
			src := *(**wasm.Reference)(unsafe.Pointer(&s[1]))
			count := s[2]
			moved := make([]wasm.Reference, count)
			for i := range moved {
				moved[i] = *(*wasm.Reference)(unsafe.Add(unsafe.Pointer(src), uintptr(i)*8))
			}
			for i := range moved {
				c.parent.parent.parent.exceptions.CopySlot(
					(*wasm.Reference)(unsafe.Add(unsafe.Pointer(dst), uintptr(i)*8)), &moved[i])
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeExnrefSlotLoad:
			// Read barrier: (execCtx, slot address) → exnref. What the slot names becomes
			// reachable from this call, so it is held before compiled code gets the handle.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Through a double pointer: a uintptr→unsafe.Pointer conversion trips checkptr.
			slot := *(**wasm.Reference)(unsafe.Pointer(&s[0]))
			s[0] = uint64(c.loadExnrefSlot(slot))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeExnrefSlotStore:
			// Write barrier: (execCtx, slot address, exnref). The slot becomes a durable
			// holder of what it names and stops being one for what it held.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			slot := *(**wasm.Reference)(unsafe.Pointer(&s[0]))
			c.storeExnrefSlot(slot, wasm.Reference(s[1]))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeAdjustExnrefs:
			// (execCtx, handle gaining a reference, handle losing one). Compiled code skips
			// the call when both are zero, so at least one is a real handle here.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			if inc := wasm.Reference(s[0]); inc != 0 {
				exn := c.heldException(inc)
				if exn == nil {
					// A handle this call cannot reach, such as one host code kept from an
					// earlier call and handed back.
					panic(wasmruntime.ErrRuntimeExpiredExceptionRef)
				}
				c.holdException(exn)
			}
			if dec := wasm.Reference(s[1]); dec != 0 {
				c.releaseException(dec)
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeNullReference:
			panic(wasmruntime.ErrRuntimeNullReference)
		default:
			panic("BUG")
		}
	}
}

func (c *callEngine) callerModuleInstance() *wasm.ModuleInstance {
	return moduleInstanceFromOpaquePtr(c.execCtx.callerModuleContextPtr)
}

// findLandingPad returns the table-driven-EH landing-pad offset for a (function-
// relative) program counter: the entry whose CallBlockStart is the greatest <= relPC.
// The table is sorted by CallBlockStart. relPC should be (returnAddr - funcBase - 1)
// so it falls inside the call instruction's block regardless of fallthrough.
func findLandingPad(tbl []wazevoapi.ExceptionTableEntry, relPC uint32) (uint32, bool) {
	idx, exact := slices.BinarySearchFunc(tbl, relPC,
		func(e wazevoapi.ExceptionTableEntry, pc uint32) int { return cmp.Compare(e.CallBlockStart, pc) })
	if !exact {
		idx-- // the search landed where relPC would go, so the entry before it is the one covering it.
	}
	if idx < 0 {
		return 0, false
	}
	return tbl[idx].LandingPad, true
}

const callStackCeiling = uintptr(50000000) // in uint64 (8 bytes) == 400000000 bytes in total == 400mb.

func (c *callEngine) growStackWithGuarded() (newSP uintptr, newFP uintptr, err error) {
	if wazevoapi.StackGuardCheckEnabled {
		wazevoapi.CheckStackGuardPage(c.stack)
	}
	newSP, newFP, err = c.growStack()
	if err != nil {
		return
	}
	if wazevoapi.StackGuardCheckEnabled {
		c.execCtx.stackBottomPtr = &c.stack[wazevoapi.StackGuardCheckGuardPageSize]
	}
	return
}

// growStack grows the stack, and returns the new stack pointer.
func (c *callEngine) growStack() (newSP, newFP uintptr, err error) {
	currentLen := uintptr(len(c.stack))
	if callStackCeiling < currentLen {
		err = wasmruntime.ErrRuntimeStackOverflow
		return
	}

	newLen := 2*currentLen + c.execCtx.stackGrowRequiredSize + 16 // Stack might be aligned to 16 bytes, so add 16 bytes just in case.
	newSP, newFP, c.stackTop, c.stack = c.cloneStack(newLen)
	c.execCtx.stackBottomPtr = &c.stack[0]
	return
}

func (c *callEngine) cloneStack(l uintptr) (newSP, newFP, newTop uintptr, newStack []byte) {
	newStack = make([]byte, l)

	relSp := c.stackTop - uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
	relFp := c.stackTop - c.execCtx.framePointerBeforeGoCall

	// Copy the existing contents in the previous Go-allocated stack into the new one.
	var prevStackAligned, newStackAligned []byte
	{
		//nolint:staticcheck
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&prevStackAligned))
		sh.Data = c.stackTop - relSp
		sh.Len = int(relSp)
		sh.Cap = int(relSp)
	}
	newTop = alignedStackTop(newStack)
	{
		newSP = newTop - relSp
		newFP = newTop - relFp
		//nolint:staticcheck
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&newStackAligned))
		sh.Data = newSP
		sh.Len = int(relSp)
		sh.Cap = int(relSp)
	}
	copy(newStackAligned, prevStackAligned)
	return
}

func (c *callEngine) stackIterator(onHostCall bool) experimental.StackIterator {
	c.stackIteratorImpl.reset(c, onHostCall)
	return &c.stackIteratorImpl
}

// stackIterator implements experimental.StackIterator.
type stackIterator struct {
	retAddrs      []uintptr
	retAddrCursor int
	eng           *engine
	pc            uint64

	currentDef *wasm.FunctionDefinition
}

func (si *stackIterator) reset(c *callEngine, onHostCall bool) {
	if onHostCall {
		si.retAddrs = append(si.retAddrs[:0], uintptr(unsafe.Pointer(c.execCtx.goCallReturnAddress)))
	} else {
		si.retAddrs = si.retAddrs[:0]
	}
	si.retAddrs = unwindStack(uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall, c.stackTop, si.retAddrs)
	si.retAddrs = si.retAddrs[:len(si.retAddrs)-1] // the last return addr is the trampoline, so we skip it.
	si.retAddrCursor = 0
	si.eng = c.parent.parent.parent
}

// Next implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) Next() bool {
	if si.retAddrCursor >= len(si.retAddrs) {
		return false
	}

	addr := si.retAddrs[si.retAddrCursor]
	cm := si.eng.compiledModuleOfAddr(addr)
	if cm != nil {
		index := cm.functionIndexOf(addr)
		def := cm.module.FunctionDefinition(cm.module.ImportFunctionCount + index)
		si.currentDef = def
		si.retAddrCursor++
		si.pc = uint64(addr)
		return true
	}
	return false
}

// ProgramCounter implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) ProgramCounter() experimental.ProgramCounter {
	return experimental.ProgramCounter(si.pc)
}

// Function implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) Function() experimental.InternalFunction {
	return si
}

// Definition implements the same method as documented on experimental.InternalFunction.
func (si *stackIterator) Definition() api.FunctionDefinition {
	return si.currentDef
}

// SourceOffsetForPC implements the same method as documented on experimental.InternalFunction.
func (si *stackIterator) SourceOffsetForPC(pc experimental.ProgramCounter) uint64 {
	upc := uintptr(pc)
	cm := si.eng.compiledModuleOfAddr(upc)
	return cm.getSourceOffset(upc)
}

// snapshot implements experimental.Snapshot
type snapshot struct {
	sp, fp, top    uintptr
	returnAddress  *byte
	stack          []byte
	savedRegisters [64][2]uint64
	ret            []uint64
	c              *callEngine
	// heldExceptions and thrown are the call's exception state at the snapshot. A restore
	// rewinds the stack the references live in, so they have to be rewound with it: the
	// locals and operand slots that took them are gone, and the compiled releases that would
	// have balanced them are on paths that no longer run.
	heldExceptions map[wasm.Reference]*exceptionRefs
	thrown         *thrownException
}

// Snapshot implements the same method as documented on experimental.Snapshotter.
func (c *callEngine) Snapshot() experimental.Snapshot {
	returnAddress := c.execCtx.goCallReturnAddress
	oldTop, oldSp := c.stackTop, uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
	newSP, newFP, newTop, newStack := c.cloneStack(uintptr(len(c.stack)) + 16)
	adjustClonedStack(oldSp, oldTop, newSP, newFP, newTop)
	return &snapshot{
		sp:             newSP,
		fp:             newFP,
		top:            newTop,
		savedRegisters: c.execCtx.savedRegisters,
		returnAddress:  returnAddress,
		stack:          newStack,
		c:              c,
		heldExceptions: c.cloneHeldExceptions(),
		thrown:         c.thrown,
	}
}

// cloneHeldExceptions copies the reference table for a snapshot. The counts are reached
// through a pointer, so the entries are copied too and not just the map around them.
func (c *callEngine) cloneHeldExceptions() map[wasm.Reference]*exceptionRefs {
	if len(c.heldExceptions) == 0 {
		return nil
	}
	out := make(map[wasm.Reference]*exceptionRefs, len(c.heldExceptions))
	for handle, e := range c.heldExceptions {
		out[handle] = &exceptionRefs{exn: e.exn, count: e.count}
	}
	return out
}

// Restore implements the same method as documented on experimental.Snapshot.
func (s *snapshot) Restore(ret []uint64) {
	s.ret = ret
	panic(s)
}

func (s *snapshot) doRestore() {
	spp := *(**uint64)(unsafe.Pointer(&s.sp))
	view := goCallStackView(spp)
	copy(view, s.ret)

	c := s.c
	c.stack = s.stack
	c.stackTop = s.top
	c.heldExceptions = s.heldExceptions
	c.thrown = s.thrown
	ec := &c.execCtx
	ec.stackBottomPtr = &c.stack[0]
	ec.stackPointerBeforeGoCall = spp
	ec.framePointerBeforeGoCall = s.fp
	ec.goCallReturnAddress = s.returnAddress
	ec.savedRegisters = s.savedRegisters
}

// Error implements the same method on error.
func (s *snapshot) Error() string {
	return "unhandled snapshot restore, this generally indicates restore was called from a different " +
		"exported function invocation than snapshot"
}

func snapshotRecoverFn(c *callEngine) {
	if r := recover(); r != nil {
		if s, ok := r.(*snapshot); ok && s.c == c {
			s.doRestore()
		} else {
			panic(r)
		}
	}
}
