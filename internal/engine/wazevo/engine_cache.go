package wazevo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"unsafe"

	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/backend"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/ssa"
	"github.com/tetratelabs/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/tetratelabs/wazero/internal/filecache"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/u32"
	"github.com/tetratelabs/wazero/internal/u64"
	"github.com/tetratelabs/wazero/internal/wasm"
)

var crc = crc32.MakeTable(crc32.Castagnoli)

// fileCacheKey returns a key for the file cache.
// In order to avoid collisions with the existing compiler, we do not use m.ID directly,
// but instead we rehash it with magic.
func fileCacheKey(m *wasm.Module) (ret filecache.Key) {
	s := sha256.New()
	s.Write(m.ID[:])
	s.Write(magic)
	// Write the CPU features so that we can cache the compiled module for the same CPU.
	// This prevents the incompatible CPU features from being used.
	cpu := platform.CpuFeatures.Raw()
	// Reuse the `ret` buffer to write the first 8 bytes of the CPU features so that we can avoid the allocation.
	binary.LittleEndian.PutUint64(ret[:8], cpu)
	s.Write(ret[:8])
	// Finally, write the hash to the ret buffer.
	s.Sum(ret[:0])
	return
}

func (e *engine) addCompiledModule(module *wasm.Module, cm *compiledModule) (c *compiledModule, err error) {
	c = e.addCompiledModuleToMemory(module, cm)
	if !module.IsHostModule && e.fileCache != nil {
		err = e.addCompiledModuleToCache(module, c)
	}
	return
}

func (e *engine) getCompiledModule(module *wasm.Module, listeners []experimental.FunctionListener, ensureTermination bool) (cm *compiledModule, ok bool, err error) {
	cm, ok = e.getCompiledModuleFromMemory(module, true)
	if ok {
		return
	}
	cm, ok, err = e.getCompiledModuleFromCache(module)
	if ok {
		cm.parent = e
		cm.module = module
		cm.sharedFunctions = e.sharedFunctions
		cm.ensureTermination = ensureTermination
		cm.offsets = wazevoapi.NewModuleContextOffsetData(module, len(listeners) > 0)
		if len(listeners) > 0 {
			cm.listeners = listeners
			cm.listenerBeforeTrampolines = make([]*byte, len(module.TypeSection))
			cm.listenerAfterTrampolines = make([]*byte, len(module.TypeSection))
			for i := range module.TypeSection {
				typ := &module.TypeSection[i]
				before, after := e.getListenerTrampolineForType(typ)
				cm.listenerBeforeTrampolines[i] = before
				cm.listenerAfterTrampolines[i] = after
			}
		}
		e.addCompiledModuleToMemory(module, cm)
		ssaBuilder := ssa.NewBuilder()
		machine := newMachine()
		be := backend.NewCompiler(context.Background(), machine, ssaBuilder)
		cm.executables.compileEntryPreambles(module, machine, be)

		// Set the finalizer.
		e.setFinalizer(cm.executables, executablesFinalizer)
	}
	return
}

func (e *engine) addCompiledModuleToMemory(m *wasm.Module, cm *compiledModule) *compiledModule {
	e.mux.Lock()
	defer e.mux.Unlock()
	if c, ok := e.compiledModules[m.ID]; ok {
		c.refCount++
		return c.compiledModule
	}
	e.compiledModules[m.ID] = &compiledModuleWithCount{compiledModule: cm, refCount: 1}
	if len(cm.executable) > 0 {
		e.addCompiledModuleToSortedList(cm)
	}
	return cm
}

func (e *engine) getCompiledModuleFromMemory(module *wasm.Module, increaseRefCount bool) (cm *compiledModule, ok bool) {
	e.mux.Lock()
	defer e.mux.Unlock()

	cmWithCount, ok := e.compiledModules[module.ID]
	if ok {
		cm = cmWithCount.compiledModule
		if increaseRefCount {
			cmWithCount.refCount++
		}
	}
	return
}

func (e *engine) addCompiledModuleToCache(module *wasm.Module, cm *compiledModule) (err error) {
	if e.fileCache == nil || module.IsHostModule {
		return
	}
	err = e.fileCache.Add(fileCacheKey(module), serializeCompiledModule(e.wazeroVersion, cm))
	return
}

func (e *engine) getCompiledModuleFromCache(module *wasm.Module) (cm *compiledModule, hit bool, err error) {
	if e.fileCache == nil || module.IsHostModule {
		return
	}

	// Check if the entries exist in the external cache.
	var cached io.ReadCloser
	cached, hit, err = e.fileCache.Get(fileCacheKey(module))
	if !hit || err != nil {
		return
	}
	defer cached.Close()

	reader := bufio.NewReader(cached)

	// Otherwise, we hit the cache on external cache.
	// We retrieve *code structures from `cached`.
	var staleCache bool
	cm, staleCache, err = deserializeCompiledModule(e.wazeroVersion, reader)
	if err != nil {
		hit = false
		return
	} else if staleCache {
		cached.Close()
		return nil, false, e.fileCache.Delete(fileCacheKey(module))
	}
	return
}

var magic = []byte{'W', 'A', 'Z', 'E', 'V', 'O'}

func serializeCompiledModule(wazeroVersion string, cm *compiledModule) io.Reader {
	buf := bytes.NewBuffer(nil)
	// First 6 byte: WAZEVO header.
	buf.Write(magic)
	// Next 1 byte: length of version:
	buf.WriteByte(byte(len(wazeroVersion)))
	// Version of wazero.
	buf.WriteString(wazeroVersion)
	// Number of *code (== locally defined functions in the module): 4 bytes.
	buf.Write(u32.LeBytes(uint32(len(cm.functionOffsets))))
	for _, offset := range cm.functionOffsets {
		// The offset of this function in the executable (8 bytes).
		buf.Write(u64.LeBytes(uint64(offset)))
	}
	// The length of code segment (8 bytes).
	buf.Write(u64.LeBytes(uint64(len(cm.executable))))
	// Append the native code.
	buf.Write(cm.executable)
	// Append checksum.
	checksum := crc32.Checksum(cm.executable, crc)
	buf.Write(u32.LeBytes(checksum))
	if sm := cm.sourceMap; len(sm.executableOffsets) > 0 {
		buf.WriteByte(1) // indicates that source map is present.
		l := len(sm.wasmBinaryOffsets)
		buf.Write(u64.LeBytes(uint64(l)))
		executableAddr := uintptr(unsafe.Pointer(&cm.executable[0]))
		for i := 0; i < l; i++ {
			buf.Write(u64.LeBytes(sm.wasmBinaryOffsets[i]))
			// executableOffsets is absolute address, so we need to subtract executableAddr.
			buf.Write(u64.LeBytes(uint64(sm.executableOffsets[i] - executableAddr)))
		}
	} else {
		buf.WriteByte(0) // indicates that source map is not present.
	}

	if tti := cm.tryTableInfo; len(tti) > 0 {
		buf.WriteByte(1) // indicates that try table info is present
		// Try-table info: per function: try_table count (uint32), then per try_table: clause count (uint32), then per clause:
		// kind (1 byte) + tagIndex (uint32).
		for _, infos := range cm.tryTableInfo {
			buf.Write(u32.LeBytes(uint32(len(infos))))
			for _, info := range infos {
				buf.Write(u32.LeBytes(uint32(len(info.CatchClauses))))
				for _, c := range info.CatchClauses {
					buf.WriteByte(c.Kind)
					buf.Write(u32.LeBytes(c.TagIndex))
				}
			}
		}
	} else {
		buf.WriteByte(0) // indicates try table info not present
	}

	if ets := cm.exceptionTables; len(ets) > 0 {
		buf.WriteByte(1) // indicates that exception table info is present
		// Exception table info: per function: entry count (uint32), then per exception table: call block start (uint32), landing pad (uint32)
		for _, tbl := range cm.exceptionTables {
			buf.Write(u32.LeBytes(uint32(len(tbl))))
			for _, entry := range tbl {
				buf.Write(u32.LeBytes(uint32(entry.CallBlockStart)))
				buf.Write(u32.LeBytes(uint32(entry.LandingPad)))
			}
		}
	} else {
		buf.WriteByte(0) // indicates exception table info not present
	}

	return bytes.NewReader(buf.Bytes())
}

func deserializeCompiledModule(wazeroVersion string, reader io.Reader) (cm *compiledModule, staleCache bool, err error) {
	cacheHeaderSize := len(magic) + 1 /* version size */ + len(wazeroVersion) + 4 /* number of functions */

	// Read the header before the native code.
	header := make([]byte, cacheHeaderSize)
	n, err := io.ReadFull(reader, header)
	if err != nil {
		if (err == io.EOF || err == io.ErrUnexpectedEOF) && n != cacheHeaderSize {
			return nil, false, fmt.Errorf("compilationcache: invalid header length: %d", n)
		}
		return nil, false, fmt.Errorf("compilationcache: error reading header: %v", err)
	}

	if !bytes.Equal(header[:len(magic)], magic) {
		return nil, false, fmt.Errorf(
			"compilationcache: invalid magic number: got %s but want %s", magic, header[:len(magic)])
	}

	// Check the version compatibility.
	versionSize := int(header[len(magic)])

	cachedVersionBegin, cachedVersionEnd := len(magic)+1, len(magic)+1+versionSize
	if cachedVersionEnd >= len(header) {
		staleCache = true
		return
	} else if cachedVersion := string(header[cachedVersionBegin:cachedVersionEnd]); cachedVersion != wazeroVersion {
		staleCache = true
		return
	}

	functionsNum := binary.LittleEndian.Uint32(header[len(header)-4:])
	cm = &compiledModule{functionOffsets: make([]int, functionsNum), executables: &executables{}}

	var eightBytes [8]byte
	for i := uint32(0); i < functionsNum; i++ {
		// Read the offset of each function in the executable.
		var offset uint64
		if offset, err = readUint64(reader, &eightBytes); err != nil {
			err = fmt.Errorf("compilationcache: error reading func[%d] executable offset: %v", i, err)
			return
		}
		cm.functionOffsets[i] = int(offset)
	}

	executableLen, err := readUint64(reader, &eightBytes)
	if err != nil {
		err = fmt.Errorf("compilationcache: error reading executable size: %v", err)
		return
	}

	if executableLen > 0 {
		executable, err := platform.MmapCodeSegment(int(executableLen))
		if err != nil {
			err = fmt.Errorf("compilationcache: error mmapping executable (len=%d): %v", executableLen, err)
			return nil, false, err
		}

		_, err = io.ReadFull(reader, executable)
		if err != nil {
			err = fmt.Errorf("compilationcache: error reading executable (len=%d): %v", executableLen, err)
			return nil, false, err
		}

		expected := crc32.Checksum(executable, crc)
		if _, err = io.ReadFull(reader, eightBytes[:4]); err != nil {
			return nil, false, fmt.Errorf("compilationcache: could not read checksum: %v", err)
		} else if checksum := binary.LittleEndian.Uint32(eightBytes[:4]); expected != checksum {
			return nil, false, fmt.Errorf("compilationcache: checksum mismatch (expected %d, got %d)", expected, checksum)
		}

		if err = platform.MprotectCodeSegment(executable); err != nil {
			return nil, false, err
		}
		cm.executable = executable
	}

	if _, err := io.ReadFull(reader, eightBytes[:1]); err != nil {
		return nil, false, fmt.Errorf("compilationcache: error reading source map presence: %v", err)
	}

	if eightBytes[0] == 1 {
		sm := &cm.sourceMap
		sourceMapLen, err := readUint64(reader, &eightBytes)
		if err != nil {
			err = fmt.Errorf("compilationcache: error reading source map length: %v", err)
			return nil, false, err
		}
		executableOffset := uintptr(unsafe.Pointer(&cm.executable[0]))
		for i := uint64(0); i < sourceMapLen; i++ {
			wasmBinaryOffset, err := readUint64(reader, &eightBytes)
			if err != nil {
				err = fmt.Errorf("compilationcache: error reading source map[%d] wasm binary offset: %v", i, err)
				return nil, false, err
			}
			executableRelativeOffset, err := readUint64(reader, &eightBytes)
			if err != nil {
				err = fmt.Errorf("compilationcache: error reading source map[%d] executable offset: %v", i, err)
				return nil, false, err
			}
			sm.wasmBinaryOffsets = append(sm.wasmBinaryOffsets, wasmBinaryOffset)
			// executableOffsets is absolute address, so we need to add executableOffset.
			sm.executableOffsets = append(sm.executableOffsets, uintptr(executableRelativeOffset)+executableOffset)
		}
	}

	if _, err := io.ReadFull(reader, eightBytes[:1]); err != nil {
		if errors.Is(err, io.EOF) {
			// No try table info - return stale cache
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("compilationcache: error reading try table info presence: %v", err)
	}

	if eightBytes[0] == 1 {
		tryTable := make([][]wazevoapi.TryTableInfo, functionsNum)
		for i := uint32(0); i < functionsNum; i++ {
			tryTableInfoCount, err := readUint32(reader, &eightBytes)
			if err != nil {
				return nil, false, fmt.Errorf("compilationcache: error reading try table[%d] entry count: %v", i, err)
			}

			if tryTableInfoCount == 0 {
				continue
			}

			tryTableInfos := make([]wazevoapi.TryTableInfo, tryTableInfoCount)
			for j := uint32(0); j < tryTableInfoCount; j++ {
				clauseCount, err := readUint32(reader, &eightBytes)
				if err != nil {
					return nil, false, fmt.Errorf("compilationcache: error reading try table[%d] entry[%d] clause count: %v", i, j, err)
				}

				catchClauses := make([]wazevoapi.CatchClauseInstance, clauseCount)
				for k := uint32(0); k < clauseCount; k++ {
					if _, err := io.ReadFull(reader, eightBytes[:1]); err != nil {
						return nil, false, fmt.Errorf("compilationcache: error reading try table[%d] entry[%d] clause[%d] kind: %v", i, j, k, err)
					}
					kind := eightBytes[0]

					tagIndex, err := readUint32(reader, &eightBytes)
					if err != nil {
						return nil, false, fmt.Errorf("compilationcache: error reading try table[%d] entry[%d] clause[%d] tag index: %v", i, j, k, err)
					}

					catchClauses[k] = wazevoapi.CatchClauseInstance{
						Kind:     kind,
						TagIndex: tagIndex,
					}
				}

				tryTableInfos[j] = wazevoapi.TryTableInfo{
					CatchClauses: catchClauses,
				}
			}
			tryTable[i] = tryTableInfos
		}
		cm.tryTableInfo = tryTable
	}

	if _, err := io.ReadFull(reader, eightBytes[:1]); err != nil {
		if errors.Is(err, io.EOF) {
			// No exception table info - return stale cache
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("compilationcache: error reading exception table presence: %v", err)
	}

	if eightBytes[0] == 1 {
		exceptionTables := make([][]wazevoapi.ExceptionTableEntry, functionsNum)
		for i := uint32(0); i < functionsNum; i++ {
			exceptionTableEntryCount, err := readUint32(reader, &eightBytes)
			if err != nil {
				return nil, false, fmt.Errorf("compilationcache: error reading exception table[%d] entry count: %v", i, err)
			}

			if exceptionTableEntryCount == 0 {
				continue
			}

			exceptionTable := make([]wazevoapi.ExceptionTableEntry, exceptionTableEntryCount)

			for j := uint32(0); j < exceptionTableEntryCount; j++ {
				callBlockStart, err := readUint32(reader, &eightBytes)
				if err != nil {
					return nil, false, fmt.Errorf("compilationcache: error reading exception table[%d] entry[%d] call block start: %v", i, j, err)
				}

				landingPad, err := readUint32(reader, &eightBytes)
				if err != nil {
					return nil, false, fmt.Errorf("compilationcache: error reading exception table[%d] entry[%d] landing pad: %v", i, j, err)
				}

				exceptionTable[j] = wazevoapi.ExceptionTableEntry{
					CallBlockStart: callBlockStart,
					LandingPad:     landingPad,
				}
			}

			exceptionTables[i] = exceptionTable
		}
		cm.exceptionTables = exceptionTables
	}
	return
}

// readUint64 strictly reads an uint64 in little-endian byte order, using the
// given array as a buffer. This returns io.EOF if less than 8 bytes were read.
func readUint64(reader io.Reader, b *[8]byte) (uint64, error) {
	s := b[0:8]
	_, err := io.ReadFull(reader, s)
	if err != nil {
		return 0, err
	}

	// Read the u64 from the underlying buffer.
	ret := binary.LittleEndian.Uint64(s)
	return ret, nil
}

// readUint32 strictly reads an uint32 in little-endian byte order, using the
// given array as a buffer.
func readUint32(reader io.Reader, b *[8]byte) (uint32, error) {
	if _, err := io.ReadFull(reader, b[:4]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:4]), nil
}
