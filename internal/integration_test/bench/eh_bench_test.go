package bench

import (
	"context"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/testing/require"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// BenchmarkEH measures wasm exception handling in the wazevo compiler along the axes
// its cost divides into: what a try_table costs when nothing throws, how that scales
// with nesting, and what a throw costs as a function of how far it propagates.
//
// Each shape runs an inner loop of `ehInner` iterations per call, so the reported
// ns/iter excludes the Go->wasm call overhead.
//
// The no-throw shapes are the ones that matter most, since they are what every program
// using exceptions pays whether or not it ever throws:
//   - enter_leave:     one catch-bearing try_table entered+left per iteration.
//   - nested_no_throw: ehDepth try_tables nested in one frame, entered+left per iter.
//   - try_call:        a try_table wrapping a real wasm call (realistic shape).
//
// The throw shapes are the rare path, split so that the fixed cost of a raise can be
// told apart from what each frame it passes through adds:
//   - same_frame_throw: throw and catch within a single frame — cheapest round-trip.
//   - throw_deep:       throw caught ehDepth call frames above.
func BenchmarkEH(b *testing.B) {
	if !platform.CompilerSupported() {
		b.Skip()
	}

	ctx := context.Background()
	cfg := wazero.NewRuntimeConfigCompiler().
		WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesExceptionHandling)
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer r.Close(ctx)

	mod, err := r.InstantiateWithConfig(ctx, buildEHBenchModule(),
		wazero.NewModuleConfig().WithStartFunctions())
	require.NoError(b, err)

	for _, shape := range []struct {
		name  string
		iters uint64
	}{
		{"enter_leave", ehInner},
		{"nested_no_throw", ehInner},
		{"try_call", ehInner},
		{"same_frame_throw", ehInner},
		{"throw_deep", ehInner},
	} {
		fn := mod.ExportedFunction(shape.name)
		require.NotNil(b, fn, shape.name)
		// Sanity-check the function runs the expected iteration count (acc == iters).
		res, err := fn.Call(ctx, shape.iters)
		require.NoError(b, err, shape.name)
		require.Equal(b, shape.iters, res[0], shape.name)

		b.Run(shape.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := fn.Call(ctx, shape.iters); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(b.Elapsed().Seconds()*1e9/float64(uint64(b.N)*shape.iters), "ns/iter")
		})
	}
}

const (
	ehInner = 10000 // try/throw iterations performed per call.
	ehDepth = 10    // call-frame / try_table nesting depth for the deep shapes.
)

// buildEHBenchModule builds a module with five exported (i32)->(i32) bench
// functions, an empty callee used by try_call, and a chain of ehDepth+1 void
// helper functions used by throw_deep.
//
// Function layout:
//
//	0 enter_leave       (type 0, exported)
//	1 nested_no_throw   (type 0, exported)
//	2 try_call          (type 0, exported)
//	3 same_frame_throw  (type 0, exported)
//	4 throw_deep        (type 0, exported)
//	5 callee            (type 1) empty, called by try_call
//	6 c0                (type 1) catcher: try_table(catch_all) { call c1 }
//	7..(6+ehDepth-1)    (type 1) c1..c_{d-1} pass-through: call next
//	6+ehDepth           (type 1) c_d thrower: throw tag0
func buildEHBenchModule() []byte {
	const (
		nLocal   = 0 // param: iteration count
		iLocal   = 1
		accLocal = 2

		calleeIndex = 5
		c0Index     = 6
	)
	cThrowIndex := c0Index + ehDepth

	accInc := []byte{
		wasm.OpcodeLocalGet, accLocal,
		wasm.OpcodeI32Const, 1,
		wasm.OpcodeI32Add,
		wasm.OpcodeLocalSet, accLocal,
	}
	// loopTail increments i and branches back to the loop while i < n.
	loopTail := []byte{
		wasm.OpcodeLocalGet, iLocal,
		wasm.OpcodeI32Const, 1,
		wasm.OpcodeI32Add,
		wasm.OpcodeLocalTee, iLocal,
		wasm.OpcodeLocalGet, nLocal,
		wasm.OpcodeI32LtS,
		wasm.OpcodeBrIf, 0, // back-edge to loop
	}
	// try_table void with a single catch_all targeting label `l`.
	tryOpen := func(l byte) []byte {
		return []byte{wasm.OpcodeTryTable, 0x40, 1, wasm.CatchKindCatchAll, l}
	}
	concat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	resultTail := []byte{wasm.OpcodeLocalGet, accLocal, wasm.OpcodeEnd} // push acc + end func

	// enter_leave: loop { block { try_table catch_all { acc++ } } loopTail }.
	enterLeave := concat(
		[]byte{wasm.OpcodeLoop, 0x40, wasm.OpcodeBlock, 0x40},
		tryOpen(0), accInc,
		[]byte{wasm.OpcodeEnd}, // end try_table
		[]byte{wasm.OpcodeEnd}, // end block
		loopTail,
		[]byte{wasm.OpcodeEnd}, // end loop
		resultTail,
	)

	// nested_no_throw: loop { block { try*ehDepth { acc++ } } loopTail }. Nothing is
	// thrown; the catch clauses only exist to force landing-pad wiring.
	nested := concat([]byte{wasm.OpcodeLoop, 0x40, wasm.OpcodeBlock, 0x40})
	for k := 0; k < ehDepth; k++ {
		// Catch label k lands any (never-taken) throw in the enclosing block.
		nested = append(nested, tryOpen(byte(k))...)
	}
	nested = append(nested, accInc...)
	for k := 0; k < ehDepth; k++ {
		nested = append(nested, wasm.OpcodeEnd) // end try_table
	}
	nested = concat(
		nested,
		[]byte{wasm.OpcodeEnd}, // end block
		loopTail,
		[]byte{wasm.OpcodeEnd}, // end loop
		resultTail,
	)

	// try_call: loop { block { try_table catch_all { call callee } } acc++ ; loopTail }.
	tryCall := concat(
		[]byte{wasm.OpcodeLoop, 0x40, wasm.OpcodeBlock, 0x40},
		tryOpen(0),
		[]byte{wasm.OpcodeCall, calleeIndex},
		[]byte{wasm.OpcodeEnd}, // end try_table
		[]byte{wasm.OpcodeEnd}, // end block
		accInc, loopTail,
		[]byte{wasm.OpcodeEnd}, // end loop
		resultTail,
	)

	// same_frame_throw: loop { block { try_table catch_all { throw } } acc++ ; loopTail }.
	sameFrame := concat(
		[]byte{wasm.OpcodeLoop, 0x40, wasm.OpcodeBlock, 0x40},
		tryOpen(0),
		[]byte{wasm.OpcodeThrow, 0},
		[]byte{wasm.OpcodeEnd}, // end try_table
		[]byte{wasm.OpcodeEnd}, // end block (catch lands here)
		accInc, loopTail,
		[]byte{wasm.OpcodeEnd}, // end loop
		resultTail,
	)

	// throw_deep: loop { call c0 ; acc++ ; loopTail }. c0 catches internally, so the
	// exception is fully unwound before the driver loop continues.
	throwDeep := concat(
		[]byte{wasm.OpcodeLoop, 0x40},
		[]byte{wasm.OpcodeCall, c0Index},
		accInc, loopTail,
		[]byte{wasm.OpcodeEnd}, // end loop
		resultTail,
	)

	// Chain helper bodies.
	// c0: block { try_table catch_all(->block) { call c1 } } — catch label 0 = block.
	c0 := concat(
		[]byte{wasm.OpcodeBlock, 0x40},
		tryOpen(0),
		[]byte{wasm.OpcodeCall, c0Index + 1},
		[]byte{wasm.OpcodeEnd}, // end try_table
		[]byte{wasm.OpcodeEnd}, // end block
		[]byte{wasm.OpcodeEnd}, // end func
	)
	chainBodies := [][]byte{c0}
	// c1..c_{ehDepth-1}: call the next function down the chain.
	for idx := c0Index + 1; idx < cThrowIndex; idx++ {
		chainBodies = append(chainBodies, []byte{wasm.OpcodeCall, byte(idx + 1), wasm.OpcodeEnd})
	}
	// c_ehDepth: throw tag 0.
	chainBodies = append(chainBodies, []byte{wasm.OpcodeThrow, 0, wasm.OpcodeEnd})

	const i32 = wasm.ValueTypeI32
	twoI32 := []wasm.ValueType{i32, i32}

	// Function types: type 0 = (i32)->(i32) for drivers, type 1 = ()->() for helpers.
	functions := []wasm.Index{0, 0, 0, 0, 0} // five drivers
	code := []wasm.Code{
		{LocalTypes: twoI32, Body: enterLeave},
		{LocalTypes: twoI32, Body: nested},
		{LocalTypes: twoI32, Body: tryCall},
		{LocalTypes: twoI32, Body: sameFrame},
		{LocalTypes: twoI32, Body: throwDeep},
		{Body: []byte{wasm.OpcodeEnd}}, // callee: empty
	}
	functions = append(functions, 1) // callee
	for _, body := range chainBodies {
		functions = append(functions, 1)
		code = append(code, wasm.Code{Body: body})
	}

	return binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{i32}, Results: []wasm.ValueType{i32}, ParamNumInUint64: 1, ResultNumInUint64: 1},
			{},
		},
		FunctionSection: functions,
		TagSection:      []wasm.Tag{{Type: 1}},
		ExportSection: []wasm.Export{
			{Name: "enter_leave", Type: wasm.ExternTypeFunc, Index: 0},
			{Name: "nested_no_throw", Type: wasm.ExternTypeFunc, Index: 1},
			{Name: "try_call", Type: wasm.ExternTypeFunc, Index: 2},
			{Name: "same_frame_throw", Type: wasm.ExternTypeFunc, Index: 3},
			{Name: "throw_deep", Type: wasm.ExternTypeFunc, Index: 4},
		},
		CodeSection: code,
	})
}
