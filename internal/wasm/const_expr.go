package wasm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero/internal/leb128"
)

type ConstantExpression struct {
	Data []byte
}

type ConstantExpressionValue struct {
	Val       uint64
	ValHi     uint64
	ValueType ValueType
}

func evaluateConstExpr(e *ConstantExpression, globalResolver func(globalIndex Index) (ValueType, uint64, uint64, error), funcRefResolver func(funcIndex Index) (Reference, error)) (ConstantExpressionValue, error) {
	var initialStack [4]uint64
	stack := initialStack[:0]
	var initialTypeStack [4]ValueType
	typeStack := initialTypeStack[:0]
	var pc uint64
	data := e.Data
	for {
		if pc >= uint64(len(data)) {
			return ConstantExpressionValue{}, io.ErrUnexpectedEOF
		}
		opCode := data[pc]
		pc++
		switch opCode {
		case OpcodeI32Const:
			v, n, err := leb128.LoadInt32(data[pc:])
			if err != nil {
				return ConstantExpressionValue{}, fmt.Errorf("read i32: %w", err)
			}
			pc += n
			stack = append(stack, uint64(uint32(v)))
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI64Const:
			v, n, err := leb128.LoadInt64(data[pc:])
			if err != nil {
				return ConstantExpressionValue{}, fmt.Errorf("read i64: %w", err)
			}
			pc += n
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeF32Const:
			if len(data[pc:]) < 4 {
				return ConstantExpressionValue{}, io.ErrUnexpectedEOF
			}
			v := binary.LittleEndian.Uint32(data[pc:])
			pc += 4
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeF32)
		case OpcodeF64Const:
			if len(data[pc:]) < 8 {
				return ConstantExpressionValue{}, io.ErrUnexpectedEOF
			}
			v := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			stack = append(stack, uint64(v))
			typeStack = append(typeStack, ValueTypeF64)
		case OpcodeGlobalGet:
			v, n, err := leb128.LoadUint32(data[pc:])
			if err != nil {
				return ConstantExpressionValue{}, fmt.Errorf("read index of global: %w", err)
			}
			pc += n
			typ, lo, hi, err := globalResolver(Index(v))
			if err != nil {
				return ConstantExpressionValue{}, err
			}
			switch typ {
			case ValueTypeV128:
				stack = append(stack, lo, hi)
			default:
				stack = append(stack, lo)
			}
			typeStack = append(typeStack, typ)
		case OpcodeRefNull:
			// Reference types are opaque 64bit pointer at runtime.
			if pc >= uint64(len(data)) {
				return ConstantExpressionValue{}, fmt.Errorf("read reference type for ref.null: %w", io.ErrShortBuffer)
			}
			b := data[pc]
			var valType ValueType
			switch b {
			case RefTypeFuncref.Kind():
				valType = RefTypeFuncref
				pc++
			case RefTypeExternref.Kind():
				valType = RefTypeExternref
				pc++
			case ValueTypeExnref.Kind():
				valType = ValueTypeExnref
				pc++
			default:
				// Concrete type index encoded as LEB128.
				typeIdx, n, err := leb128.LoadUint32(data[pc:])
				if err != nil {
					return ConstantExpressionValue{}, fmt.Errorf("invalid type for ref.null: 0x%x", b)
				}
				pc += n
				valType = ValueTypeConcreteRef(typeIdx, true)
			}
			stack = append(stack, 0)
			typeStack = append(typeStack, valType)
		case OpcodeRefFunc:
			v, n, err := leb128.LoadUint32(data[pc:])
			if err != nil {
				return ConstantExpressionValue{}, fmt.Errorf("read i32: %w", err)
			}
			pc += n
			ref, err := funcRefResolver(Index(v))
			if err != nil {
				return ConstantExpressionValue{}, err
			}
			stack = append(stack, uint64(ref))
			typeStack = append(typeStack, ValueTypeFuncref)
		case OpcodeVecPrefix:
			if data[pc] != OpcodeVecV128Const {
				return ConstantExpressionValue{}, fmt.Errorf("invalid vector opcode for const expression: %#x", data[pc-1])
			}
			pc++
			if len(data[pc:]) < 16 {
				return ConstantExpressionValue{}, fmt.Errorf("%s needs 16 bytes but was %d bytes", OpcodeVecV128ConstName, len(data[pc:]))
			}
			lo := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			hi := binary.LittleEndian.Uint64(data[pc:])
			pc += 8
			stack = append(stack, lo, hi)
			typeStack = append(typeStack, ValueTypeV128)
		case OpcodeI32Add:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i32.add")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i32.add: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)+uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI32Sub:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i32.sub")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i32.sub: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)-uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI32Mul:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i32.mul")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI32 || v2 != ValueTypeI32 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i32.mul: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, uint64(uint32(a)*uint32(b)))
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI32)
		case OpcodeI64Add:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i64.add")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i64.add: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a+b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeI64Sub:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i64.sub")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i64.sub: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a-b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeI64Mul:
			if len(typeStack) < 2 {
				return ConstantExpressionValue{}, errors.New("stack underflow on i64.mul")
			}
			v1 := typeStack[len(typeStack)-1]
			v2 := typeStack[len(typeStack)-2]
			if v1 != ValueTypeI64 || v2 != ValueTypeI64 {
				return ConstantExpressionValue{}, fmt.Errorf("type mismatch on i64.mul: %s, %s", ValueTypeName(v2), ValueTypeName(v1))
			}
			b, a := stack[len(stack)-1], stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a*b)
			typeStack = typeStack[:len(typeStack)-2]
			typeStack = append(typeStack, ValueTypeI64)
		case OpcodeEnd:
			if len(typeStack) != 1 {
				return ConstantExpressionValue{}, errors.New("stack has more than one value at end of constant expression")
			}

			typ := typeStack[0]

			switch typ {
			case ValueTypeV128:
				if len(stack) != 2 {
					return ConstantExpressionValue{}, errors.New("stack has an invalid number of values after expression evaluation")
				}
				return ConstantExpressionValue{Val: stack[0], ValHi: stack[1], ValueType: ValueTypeV128}, nil
			default:
				return ConstantExpressionValue{Val: stack[0], ValueType: typ}, nil
			}
		default:
			return ConstantExpressionValue{}, fmt.Errorf("invalid opcode for const expression: 0x%x", opCode)
		}
	}
}

func evaluateConstExprInModuleInstance(e *ConstantExpression, m *ModuleInstance) ConstantExpressionValue {
	v, _ := evaluateConstExpr(
		e,
		func(globalIndex Index) (ValueType, uint64, uint64, error) {
			g := m.Globals[globalIndex]
			return g.Type.ValType, g.Val, g.ValHi, nil
		},
		func(funcIndex Index) (Reference, error) {
			return m.Engine.FunctionInstanceReference(funcIndex), nil
		},
	)
	return v
}

func NewConstantExpressionFromOpcode(
	opcode byte, opData []byte,
) ConstantExpression {
	data := make([]byte, 0, 3+len(opData)) // 2 for opcode and optional vec prefix, 1 for end
	if opcode == OpcodeVecV128Const {
		data = append(data, OpcodeVecPrefix)
	}
	data = append(data, opcode)
	data = append(data, opData...)
	data = append(data, OpcodeEnd)
	return ConstantExpression{Data: data}
}

func NewConstantExpressionFromI32(val int32) ConstantExpression {
	return NewConstantExpressionFromOpcode(OpcodeI32Const, leb128.EncodeInt32(val))
}

func NewConstantExpressionFromI64(val int64) ConstantExpression {
	return NewConstantExpressionFromOpcode(OpcodeI64Const, leb128.EncodeInt64(val))
}
