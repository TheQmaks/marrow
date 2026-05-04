# Marrow examples

Реальные Java-программы + Marrow скрипты. Каждый показывает применение
определённого примитива framework'а.

## Mental model

Marrow даёт **примитивы** (не готовые сценарии). Frida-эквивалентный API:

```js
// Find live instances of a class.
Java.choose('Game', {
    onMatch: function(g) {
        // g is an instance proxy with .field.value getters/setters
        g.score.value = 99999;
        g.health.value = 100;
    }
});

// Wrap an arbitrary oop into the same proxy shape.
var u = Java.cast(userOopHex, 'User');
u.email.value = '...';

// Hook a method, get arg objects as oops, cast them.
App.processOrder.implementation = function(orderOop) {
    var o = Java.cast(orderOop, 'Order');
    o.totalPrice.value = 0;
};
```

`Java.cast()` lazy-builds a proxy by reading the class's field metadata
(via `_klassFields`). Each field becomes an object with `.value` getter/setter
that reads the field of the underlying oop. Setter auto-converts JS Numbers
to hex strings for J/D types so `.value = 1000000` just works for longs.

## Run pattern

```bash
cd 11_object_arg
javac App.java
"$JAVA_HOME/bin/java.exe" App &
PID=<pid_of_java>
"../cpp/build/Release/marrow.exe" inject $PID \
    "../cpp/build/Release/marrow_agent.dll"
"../cpp/build/Release/marrow.exe" agent $PID \
    eval "$(cat attack.js)"
```

## Demo index

| # | Scenario | Primitive |
|---|---|---|
| 01 | License bypass | `T.method.setReturn(value)` |
| 02 | Password sniffer | `T.method.implementation = fn` + arg decode |
| 03 | Live game cheat | `Java.choose` + `instance.field.value` |
| 04 | Hot method profiler | `Java.traceClass` + `readTraces` |
| 05 | Crypto plaintext | hook `Cipher.doFinal`, decode byte[] arg |
| 06 | Memory leak | `Java.snapshotForDiff` |
| 07 | HW field watch | `Java.watchField` (DR0-3) |
| 08 | HTTP introspection | hook `URL`/`HttpURLConnection` |
| 09 | Native recv hook | `Java.onNative('ws2_32.dll', 'recv')` |
| 10 | Hotkey-driven cheat | `Java.onKey` + static field mutation |
| **11** | **Object-arg modify** | hook fn, `Java.cast(argOop, ClassName)`, mutate fields |
| **12** | **Multi-arg inspection** | same, decode every object arg incl. nested Strings |
| **13** | **Ergonomic cheat suite** | full UI: hotkey toggles cheat suite via Java.onKey |

## Что мы НЕ делаем "из коробки"

В отличие от ранних версий, мы не shipping pre-baked сценарии типа
`traceCrypto`/`traceNetwork` как первоклассные API. Они остались в bootstrap
как опциональные хелперы (`Java.traceCrypto(fn)`), но это просто примеры
композиции примитивов. **Реальные tracing scripts пользователь пишет сам**
из `Java.use('javax/crypto/Cipher').doFinal.implementation = fn` и т.п.

## Уникально у нас (Frida не делает)

- HW debug-register field watch (Demo 07)
- Direct heap class histogram diff (Demo 06)
- Klass cloning at metadata level (`Java.cloneClass`)
- ConstantPool raw inspection
- Bytecode redefine (full method body swap)
- Out-of-process operation through `RemoteReader` (no DLL injection needed)
