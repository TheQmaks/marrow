# Marrow API Reference

140+ bindings across `Java.*` (high-level Frida-style) and `Marrow.*` (low-level
primitives). This document covers all exposed JavaScript APIs for in-process
HotSpot inspection and manipulation through the agent.

---

## Java.* — High-Level API

Frida-equivalent helpers for the majority of use cases. All users should start here.

### Class Loading & Introspection

| Function | Signature | Description |
|----------|-----------|-------------|
| `use` | `(name: string) -> ClassProxy` | Load a class by name and return a proxy with method handles + instance fields |
| `cast` | `(oopHex: string, className: string) -> InstanceProxy` | Wrap an oop into an instance proxy with direct property access per class fields |
| `fields` | `(className: string, includeStatic?: boolean) -> FieldInfo[]` | Enumerate all field metadata (instance + static if requested) |
| `threads` | `() -> ThreadInfo[]` | JS view of all JavaThreads with state/id/status |
| `threadsNamed` | `() -> ThreadInfo[]` | Combine threads() with threadName resolution for human-readable names |

### Class Inspection

| Function | Signature | Description |
|----------|-----------|-------------|
| `checkJit` | `(className: string) -> MethodInfo[]` | Inspect which methods are currently JIT-compiled; returns {name, sig, jitCompiled, codePtr} |
| `cloneClass` | `(donorClassName: string, newName: string) -> string` | L1 clone of a class (registered in CLDG); returns new Klass hex addr |

### Heap Snapshot & Inspection

| Function | Signature | Description |
|----------|-----------|-------------|
| `snapshotHeap` | `(topN?: number) -> ClassSnapshot[]` | Top N most-populated classes by instance count; returns [{name, count, klass}] |
| `snapshotForDiff` | `() -> DiffHelper` | Heap diff: snapshot now, return helper with `.diff()` for leak hunting (Frida-style) |
| `choose` | `(name: string, callbacks: {onMatch, onComplete, limit?}) -> number` | Enumerate all instances of a class; fires onMatch per instance, returns count |
| `findBy` | `(className, fieldName, type?, expectedValue, limit?) -> Oop[]` | Race-free filter walker; find oops by field match (wrapped in Java.safe) |
| `heapScan` | `(nameSubstr: string, max?: number) -> Oop[]` | Find oops of any class matching name substring |
| `heapRegions` | `(minMB?: number) -> MemoryRegion[]` | Major writable memory regions in process |

### Method Hooks & Callbacks

| Function | Signature | Description |
|----------|-----------|-------------|
| `.attach` | `(fn: function) -> this` | Append fn to the chain so multiple JS callbacks fire per call; fluent |
| `.overload` | `(sig: string) -> MethodHandle` | Select a specific overload by JVM signature |
| `implementation` | `getter/setter: function \| null` | Replace method implementation; set to null to unhook and restore original |
| `.detachAll` | `() -> this` | Remove all attached implementations for a method |
| `drain` | `() -> number` | Drain accumulated invocations; fires all chained handlers; returns count |

### Method Invocation

| Function | Signature | Description |
|----------|-----------|-------------|
| `invoke` | `(method, thisOop: string, args: any[]) -> string` | Invoke instance method synchronously; returns RAX as hex string (up to 4 args) |
| `invokeStatic` | `(method, args: any[]) -> string` | Invoke static method synchronously; returns RAX as hex string (up to 4 args) |
| `redefineMethod` | `(method, bytecode: number[]) -> boolean` | Wholesale bytecode swap; replaces method body with new bytecode |

### Argument Decoding

| Function | Signature | Description |
|----------|-----------|-------------|
| `parseSig` | `(sig: string) -> {args, ret}` | Parse JVM method signature like "(IJLjava/lang/String;[B)V" into typed args |
| `decodeArgs` | `(cookie, sig, isInstance, thisClassName?) -> Slot[]` | Decode captured args at hook entry; handles interpreter + JIT paths |
| `decodeArgsAt` | `(cookie, sig, isInstance, eventIndex, thisClassName?) -> Slot[]` | Decode args from specific ring-buffer event |
| `regs` | `(cookie) -> RegisterMap` | Latest CPU registers {rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi,r8..r15} as hex |
| `stack` | `(cookie) -> string[]` | Latest stack snapshot at method entry (16 qwords from retaddr) |
| `opstack` | `(cookie, n?: number) -> string[]` | N qwords from captured operand stack |

### Memory Access

| Function | Signature | Description |
|----------|-----------|-------------|
| `readField` | `(oopHex: string, klassName: string, fieldName: string) -> any` | Read one instance field from a live oop; auto-suspend for java/lang/String |
| `writeField` | `(oopHex: string, klassName: string, fieldName: string, value: any) -> boolean` | Mutate one instance field; values must match field signature |
| `readArray` | `(oopHex: string, type: string, max?: number) -> any[]` | Read array elements (I/J/F/D/B/S/C/Z/L/[); J/D returned as hex strings |
| `readMem` | `(addrHex: string, n: number) -> number[]` | Raw memory read; returns byte array (0..255) |
| `writeMem` | `(addrHex: string, bytes: number[]) -> boolean` | Raw memory write |
| `toString` | `(oopHex: string) -> string` | Decode java.lang.String oop into UTF-8 |

### Hardware Watchpoints (CPU Debug Registers)

| Function | Signature | Description |
|----------|-----------|-------------|
| `watchField` | `(className: string, fieldName: string, length?: number) -> number` | Hardware watchpoint on static reference field (DR0-DR3); returns cookie |
| `unwatch` | `(cookie: number) -> boolean` | Remove hardware watchpoint |
| `drainWatches` | `() -> WatchEvent[]` | Drain pending write-detect events |
| `watchAll` | `(addrs: {addr, length}[]) -> number[]` | Watch up to 4 addresses simultaneously; returns cookies |
| `unwatchAll` | `(cookies: number[]) -> boolean` | Remove multiple watchpoints |

### Input Events (Keyboard & Mouse)

| Function | Signature | Description |
|----------|-----------|-------------|
| `onKey` | `(vk: number, fn: function) -> void` | Register callback for Win32 virtual-key code (0x70..0x7B = F1..F12, 0x41 = A) |
| `tickKeys` | `() -> number` | Drain pending key events and invoke registered handlers; returns count |
| `drainKeys` | `() -> KeyEvent[]` | Drain raw key events without invoking handlers |
| `onClick` | `(button: number, fn: function) -> void` | Register mouse button click callback (0=left, 1=right, 2=middle) |
| `tickMouse` | `() -> number` | Drain pending mouse events and fire registered handlers |
| `mousePos` | `() -> {x, y}` | Current mouse cursor position |
| `drainMouse` | `() -> MouseEvent[]` | Drain raw mouse events |

### Bytecode & JIT

| Function | Signature | Description |
|----------|-----------|-------------|
| `dumpBytecode` | `(method) -> number[] \| null` | Extract bytecode as byte array (0..255); null for native/abstract |
| `forceCompile` | `(method) -> boolean` | Bump invocation counter past JIT threshold; next dispatch triggers compilation |

### Tracing

| Function | Signature | Description |
|----------|-----------|-------------|
| `traceClass` | `(className: string, cookieBase?: number) -> {cookieBase, installed, methods}` | Install counting hook on every method; returns metadata for trace reading |
| `readTraces` | `(traceResult) -> TraceEntry[]` | Extract counts from traceClass result; sorted by invocation count desc |
| `traceAll` | `(classPattern: string, methodPattern: string, cookieBase?: number, maxN?: number) -> void` | Substring-match; pre-install counting hooks on every match |
| `backtrace` | `(cookie: number, max?: number) -> StackFrame[]` | Call stack at last hook fire (interpreted frames + Java method names) |

### Object Inspection

| Function | Signature | Description |
|----------|-----------|-------------|
| `explore` | `(oopHex: string, depth?: number) -> ObjectTree` | Recursive object inspection; wrapped in Java.safe for CP-mutation safety |
| `lockOwner` | `(oopHex: string) -> {state, owner, mark}` | Who holds the monitor on this object; returns lock metadata |
| `mhDump` | `(oopHex: string) -> MethodHandleInfo` | Invoke API helper; decode java.lang.invoke.MethodHandle |
| `callsiteTarget` | `(oopHex: string) -> any` | Get target of a java.lang.invoke.CallSite |

### Code Cache & Compilation

| Function | Signature | Description |
|----------|-----------|-------------|
| `codeCache` | `(maxN?: number) -> NMethod[]` | All JIT'd nmethods reachable from loaded classes; sorted by size desc |

### Native Function Hooks

| Function | Signature | Description |
|----------|-----------|-------------|
| `onNative` | `(va_hex: string, fn: function) -> number` | Install inline hook on a native VA; store JS callback; hookId or -1 on error |
| `tickNative` | `() -> number` | Drain captured invocations and fire fn(rcx, rdx, r8, r9, event); returns count |

### Utilities

| Function | Signature | Description |
|----------|-----------|-------------|
| `enumerateClassLoaders` | `(callbacks: {onMatch, onComplete}) -> number` | Enumerate ClassLoaderData entries (Frida-style callback API) |
| `cpDump` | `(className: string, maxEntries?: number) -> ConstantPoolEntry[]` | Race-free CP dump; wrapped in Java.safe; returns entries |
| `methodName` | `(methodPtrHex: string) -> string` | Symbolicator: methodPtr (hex) -> "ClassName.method(sig)" |
| `threadName` | `(threadObjOop: string) -> string` | Decode java.lang.Thread.name field |
| `systemPropsOop` | `() -> string` | Oop of System.props (java.util.Properties) |
| `toast` | `(title?: string, body?: string) -> boolean` | Windows tray balloon notification |
| `safe` | `(closure: function) -> any` | Suspend all OTHER threads, run closure, resume; foundation for race-free ops |
| `suspendAll` | `() -> number` | Suspend all threads; returns count |
| `resumeAll` | `() -> number` | Resume all threads; returns count |
| `ptr` | `(va: string \| number) -> NativePointer` | NativePointer wrapper; Frida-equivalent ergonomic API for raw VAs |
| `memscan` | `(moduleName: string, pattern: string, limit?: number) -> Address[]` | Byte-pattern memory scan; pattern "13 37 ?? ??" |
| `hooks` | `(min?: number, max?: number) -> HookCount[]` | List installed hook counters in range |

### Window & Display

| Function | Signature | Description |
|----------|-----------|-------------|
| `windows` | `() -> WindowInfo[]` | Enumerate all top-level windows |
| `findWindow` | `(className: string, titlePattern?: string) -> WindowHandle` | Find window by class + optional title match |
| `activeWindow` | `() -> WindowHandle` | Get foreground window handle |
| `setForeground` | `(hwnd: number) -> boolean` | Set window to foreground |

### GUI Input (Cursor Control)

| Function | Signature | Description |
|----------|-----------|-------------|
| `setCursor` | `(x: number, y: number) -> boolean` | Move mouse cursor |
| `click` | `(button?: number) -> boolean` | Click at current position (0=left) |
| `clickAt` | `(x: number, y: number, button?: number) -> boolean` | Click at absolute coordinates |
| `scroll` | `(delta: number) -> boolean` | Scroll (positive=down, negative=up) |
| `drag` | `(fromX, fromY, toX, toY, button?) -> boolean` | Drag mouse from->to |

---

## Marrow.* — Low-Level Bindings

Direct access to C-side primitives. Use these when composing new `Java.*` helpers; most users should not need these directly.

### Class & Method Metadata

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `findClass` | `(name: string)` | `{lo, hi, addr}` | Find Klass* by name; returns null if not loaded |
| `findMethod` | `(klass, name: string)` | `{addr, name, sig, codeSize}` | Find Method* within a Klass |
| `listMethods` | `(klass)` | `MethodInfo[]` | All methods of a class: {name, sig, codeSize, addr} |
| `_klassFields` | `(klass, includeStatic: boolean)` | `FieldInfo[]` | Walk field stream; returns [{name, offset, sig}, ...] |
| `_klassSupers` | `(klass)` | `Klass[]` | Superclass chain (not including Object if not present) |
| `_klassInterfaces` | `(klass)` | `Klass[]` | Direct interfaces |
| `_klassSubclasses` | `(klass)` | `Klass[]` | Direct subclasses |

### Hook Installation & Management

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_installImpl` | `(method_lo, method_hi, cookie, label)` | `true` | Install callback hook on Method* with JS-side cookie |
| `_uninstallImpl` | `(method_lo, method_hi)` | `boolean` | Uninstall hook; restores original bytecode + entries |
| `_drainImplEvents` | `()` | `Event[]` | Drain pending fires: [{cookie, label, delta, total}] |
| `_muteMethod` | `(method_lo, method_hi)` | `true` | Replace bytecode with return; caller's JS hook fires, original skipped |
| `_setReturnInt` | `(method_lo, method_hi, value)` | `true` | Bytecode patch for int-return override (bipush/sipush range) |
| `_setReturnNull` | `(method_lo, method_hi)` | `true` | Bytecode patch for oop-return override (aconst_null; areturn) |
| `_traceClass` | `(klass, cookieBase: number)` | `number` | Install counting hooks on all methods; returns count installed |
| `hookCount` | `(klass, methodName, cookie)` | `boolean` | Legacy: install counting hook and read via readCount |

### Register & Stack Capture

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_lastRegs` | `(cookie, eventIndex?)` | `[u64 * 16]` | Latest CPU registers as array; index order: rax,rcx,rdx,... |
| `_lastStack` | `(cookie, eventIndex?)` | `[u64 * 16]` | Latest stack snapshot at method entry |
| `_lastVia` | `(cookie, eventIndex?)` | `0 \| 1` | Entry path: 0=interpreter, 1=JIT-compiled |
| `_ringHead` | `(cookie)` | `number` | Current ring-buffer head (monotonic) for snapshot iteration |

### Memory I/O

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_readMem` | `(addrHex, n: number)` | `byte[]` | Read n bytes from VA; returns array (0..255) |
| `_writeMem` | `(addrHex, bytes: number[])` | `boolean` | Write bytes to VA |
| `_readInstanceField` | `(oopHex, klass, fieldName)` | `any` | Read one instance field; primitives as Number, longs/refs as hex |
| `_writeInstanceField` | `(oopHex, klass, fieldName, value)` | `boolean` | Write one instance field |
| `_fieldSlotAddr` | `(klass, fieldName)` | `{lo, hi, addr}` | Absolute address of static field's holding slot |
| `readCount` | `(cookie)` | `number` | Read fire-count from a counting hook cookie |
| `readStaticRef` | `(klass, fieldName)` | `string \| null` | Read static field; returns oop hex or null |
| `readStaticString` | `(klass, fieldName)` | `string \| null` | Read & decode static String field to UTF-8 |
| `writeStaticRef` | `(kdst, fdst, ksrc, fsrc)` | `boolean` | Copy oop value from one static field to another |
| `_opgackRead` | `(cookie, n: number)` | `[hex, ...]` | N qwords from operand stack snapshot |

### Heap Walking & Snapshots

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `findInstances` | `(klass, limit?: number)` | `Oop[]` | All oops of a class; returns hex strings |
| `_findInstancesByField` | `(klass, fieldName, type, expectedValue, limit)` | `Oop[]` | Find oops where fieldName matches value (race-free via Java.safe) |
| `snapshotHeap` | `(topN?: number)` | `{name, count, klass}[]` | Top N classes by instance count |
| `_heapScanByName` | `(nameSubstr, max)` | `Oop[]` | Find oops matching class name substring |
| `_heapRegions` | `(minMB: number)` | `MemoryRegion[]` | Major writable regions in process |

### Method Invocation & Entry

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_invokeInstance` | `(m_lo, m_hi, this, a0_lo, a0_hi, ..., a3_lo, a3_hi)` | `hex` | Call instance method; returns RAX as hex string |
| `_invokeStatic` | `(m_lo, m_hi, a0_lo, a0_hi, ..., a3_lo, a3_hi)` | `hex` | Call static method; returns RAX as hex string |

### String & Array Access

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_toString` | `(oopHex)` | `string` | Decode java.lang.String oop; internally suspends threads for CP safety |
| `_readArray` | `(oopHex, type: char, max: number)` | `any[]` | Read array; type I/J/F/D/B/S/C/Z/L/[; longs as hex |

### Hardware Watchpoints

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `watchAddr` | `(addr_lo, addr_hi, length, slot)` | `cookie` | Set debug register watchpoint; slot 0-3 |
| `unwatch` | `(cookie)` | `boolean` | Remove watchpoint |
| `drainWatches` | `()` | `WatchEvent[]` | Drain pending {addr, fault_rip, delta_count} events |
| `_watchAll` | `(addrs: {addr, length}[])` | `cookie[]` | Multi-address watch (up to 4) |
| `_unwatchAll` | `(cookies: number[])` | `boolean` | Unwatch multiple |

### Input Events

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_registerKey` | `(vk: number)` | `void` | Register virtual-key for polling |
| `_drainKeys` | `()` | `KeyEvent[]` | Drain pending: [{vk, delta}] |
| `_registerMouse` | `(button: number)` | `void` | Register mouse button for polling |
| `_drainMouse` | `()` | `MouseEvent[]` | Drain pending: [{button, delta, x, y}] |
| `_mousePos` | `()` | `{x, y}` | Current cursor position |

### Bytecode & Disassembly

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_dumpBytecode` | `(method_lo, method_hi)` | `byte[] \| null` | Extract bytecode; null for native/abstract |
| `_disasm` | `(addr_lo, addr_hi, maxBytes)` | `InsnInfo[]` | Disassemble native code: [{addr, mnemonic, operands}] |
| `_redefineMethod` | `(method_lo, method_hi, bytecode)` | `boolean` | Swap method bytecode wholesale |

### JIT & Code Cache

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `checkJit` | `(klass)` | `MethodInfo[]` | Which methods are JIT-compiled: [{name, sig, jitCompiled, codePtr}] |
| `_forceCompile` | `(method_lo, method_hi)` | `boolean` | Bump invocation counter; triggers JIT on next interpreter dispatch |
| `_codeCache` | `(maxN: number)` | `{nmethod, size, method, name}[]` | All nmethods; sorted by size |
| `_nmDump` | `(nmethod_lo, nmethod_hi)` | `NMethodInfo` | nmethod metadata: {entry, size, method, isNative} |

### Call Stack & Threading

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_backtrace` | `(cookie, max)` | `StackFrame[]` | Call stack at last hook fire; method names resolved |
| `_stackWalk` | `(threadObj)` | `StackFrame[]` | Walk a JavaThread's call stack |
| `threads` | `()` | `ThreadInfo[]` | All threads: {id, status, threadObj, nativeId} |
| `_threadName` | `(threadObj)` | `string` | Decode java.lang.Thread.name field |

### Object Metadata & Exploration

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_cpDump` | `(klass, maxEntries)` | `ConstantPoolEntry[]` | Constant pool entries; ConstantPool mutated by interpreter, so wrapped in Java.safe |
| `_explore` | `(oopHex, depth)` | `ObjectTree` | Recursive object graph from oop; wrapped in Java.safe |
| `_monitorState` | `(oopHex)` | `{state, owner, mark}` | Monitor lock metadata |
| `_mhDump` | `(oopHex)` | `MethodHandleInfo` | java.lang.invoke.MethodHandle metadata |
| `_callsiteTarget` | `(oopHex)` | `any` | java.lang.invoke.CallSite target |

### Class Cloning & Management

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `cloneClass` | `(donor, newName)` | `{lo, hi, addr}` | L1 clone (registered in CLDG); returns new Klass* |
| `classLoaders` | `()` | `ClassLoaderData[]` | All ClassLoaderData: {addr, klasses, name} |

### Native Inline Hooks

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_inlineHook` | `(va_hex, callback_idx)` | `hookId` | Install hook on native VA (legacy callback) |
| `_inlineHookV2` | `(va_hex)` | `hookId` | Install hook returning hookId for drain |
| `_inlineUnhook` | `(hookId)` | `boolean` | Remove inline hook |
| `_inlineHookCount` | `(hookId)` | `number` | Fire count for hook |
| `_inlineHookHead` | `(hookId)` | `number` | Ring-buffer head |
| `_inlineHookSnap` | `(hookId, index)` | `{rcx, rdx, r8, r9}` | Snapshot of args for event |
| `_onNativeDrain` | `(hookId, maxEvents)` | `Event[]` | Drain: [{rcx, rdx, r8, r9}] |

### Memory & Modules

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `modules` | `()` | `ModuleInfo[]` | Loaded DLLs/SOs: {name, base, size} |
| `moduleAt` | `(va_hex)` | `ModuleInfo \| null` | Which module contains address |
| `symbolAt` | `(va_hex)` | `string \| null` | Symbol name at address (if debug info available) |
| `_methodName` | `(methodPtr_hex)` | `{className, name, sig}` | Resolve Method* to human name |
| `_memscan` | `(moduleName, pattern, limit)` | `Address[]` | Scan: "13 37 ?? ??" syntax |

### Allocation Tracking

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_allocStart` | `()` | `boolean` | Begin tracking allocations |
| `_allocStop` | `()` | `boolean` | End tracking |
| `_allocStats` | `()` | `AllocStats` | Current stats: {count, totalBytes} |
| `_allocReset` | `()` | `void` | Reset counters |

### Diagnostics & Events

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `diagnose` | `()` | `DiagnosticInfo` | Runtime diagnostics: JVM version, heap size, thread count, etc. |
| `event` | `(name, data)` | `void` | Fire custom event (for app-level logging) |
| `_eventDrain` | `()` | `Event[]` | Drain event queue |
| `_memlogPush` | `(msg: string)` | `void` | Push message to memory log |
| `_memlogList` | `()` | `string[]` | Retrieve all logged messages |
| `_memlogClear` | `()` | `void` | Clear memory log |

### Mass Tracing

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_traceMatching` | `(classPat, methodPat, cookieBase, maxN)` | `number` | Substring-match classes & methods; install counting hooks on all matches |
| `_hookCounts` | `(min, max)` | `{cookie, count}[]` | List all hooks in range with their fire counts |

### Graphics Overlay (Game Modding)

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_glDiscover` | `()` | `{version, vendor}` | Detect OpenGL; returns null if not found |
| `_glHookFrames` | `(callback_idx)` | `boolean` | Install hook on glSwapBuffers; fires per frame |
| `_glFrameCount` | `()` | `number` | Current frame count |

### System Info

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_systemPropsOop` | `()` | `string` | Oop of java.util.Properties (System.getProperties) |
| `_heapRegions` | `(minMB)` | `MemoryRegion[]` | Writable regions: {addr, size, protections} |

### Thread Suspension (Safe Context)

| Binding | Args | Returns | Description |
|---------|------|---------|-------------|
| `_suspendAll` | `()` | `number` | Suspend all threads; returns count |
| `_resumeAll` | `()` | `number` | Resume all threads; returns count |

---

## NativePointer Methods

The `Java.ptr(va)` helper returns a NativePointer object with Frida-compatible ergonomic methods:

```javascript
var p = Java.ptr('0x12345678');
p.add(8).readU32();       // Arithmetic + read
p.readU8();               // Single byte
p.readU16();              // 2-byte unsigned
p.readU32();              // 4-byte unsigned
p.readU64();              // 8-byte (returns hex string)
p.readBytes(n);           // n bytes
p.readUtf8(n);            // n bytes as UTF-8 string (null-terminated)
p.writeBytes([0x90, 0x90]); // Write bytes
p.writeU8(0xFF);          // Write single byte
p.writeU16(0xFFFF);       // Write 2-byte
p.writeU32(0xFFFFFFFF);   // Write 4-byte
p.toString();             // Hex string representation
```

---

## Type Tags (JVM Signature Characters)

Used in method signatures and type specifications:

| Tag | Meaning | Java Type |
|-----|---------|-----------|
| `V` | void | (no return) |
| `I` | int | 32-bit signed integer |
| `Z` | boolean | true/false (1/0) |
| `B` | byte | 8-bit signed integer |
| `C` | char | 16-bit unicode |
| `S` | short | 16-bit signed integer |
| `J` | long | 64-bit signed integer |
| `F` | float | 32-bit IEEE-754 |
| `D` | double | 64-bit IEEE-754 |
| `L` | object reference | (class name follows; semicolon terminates) |
| `[` | array | (element type follows) |

Example: `(IJLjava/lang/String;[B)V` = method taking int, long, String, byte[], returning void.

---

## Error Handling

All bindings use Duktape's error system:
- Null returns indicate failure (e.g., class not found)
- Exceptions are logged via `Marrow.log()` but do not stop the agent
- JavaScript errors in callbacks (hooks, listeners) are caught and logged
- Use try/catch in callbacks to prevent propagation

---

## Notes

- **Frida compatibility**: Java.* API mirrors Frida's `Java` object for familiar syntax
- **Two levels**: Java.* for user scripts; Marrow.* for building new abstractions
- **Thread safety**: Methods marked with Java.safe() automatically suspend/resume
- **Bytecode mutation**: Hooking replaces bytecode; unset `.implementation = null` to restore
- **Hardware watchpoints**: Limited to 4 simultaneous (x64 DR0-DR3)
- **String decoding**: Requires StringReader initialization (first call to toString costs extra)

---

**Project**: Marrow (HotSpot reader/writer/allocator/invoker; no JNI/JVMTI)
**Supported JDKs**: 8 through 25 (empirically verified)
