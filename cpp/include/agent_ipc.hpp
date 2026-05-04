#pragma once
// Shared-memory IPC between external CLI and injected agent DLL.
//
// Layout (named file mapping "Local\marrow-agent-<pid>"):
//   +0x0000  magic           'JPAG' (signature)
//   +0x0004  state           enum { IDLE=0, REQUEST=1, PROCESSING=2, REPLY=3 }
//   +0x0008  request_id      client-provided, echoed in reply
//   +0x0010  cmd             enum CommandId
//   +0x0014  arg_count       number of 8-byte args in `args[]`
//   +0x0018  args[0..15]     up to 16 uint64_t args
//   +0x0098  status          0 = OK, nonzero = error
//   +0x00A0  result[0..15]   up to 16 uint64_t return values
//   +0x0120  msg_len         length of error/log message (bytes)
//   +0x0128  msg[0..4095]    UTF-8 buffer for strings / errors
//
// Total 16 KiB page, aligned to allocation granularity.

#include <cstdint>

namespace marrow {

constexpr uint32_t AGENT_IPC_MAGIC   = 0x4741504A; // 'JPAG'
constexpr size_t   AGENT_IPC_SIZE    = 16384;
constexpr size_t   AGENT_IPC_MSG_MAX = 4096;

enum class IpcState : uint32_t {
    Idle       = 0,
    Request    = 1,
    Processing = 2,
    Reply      = 3,
};

enum class CommandId : uint32_t {
    Ping         = 0,  // no args, reply OK
    FindClass    = 1,  // args[0] = addr of UTF-8 name (in msg buffer, offset 0)
    ReadField    = 2,  // args[0]=klass, args[1]=addr of field-name
    WriteFieldRef= 3,  // args[0]=klass, args[1]=field-name-off, args[2]=src-klass, args[3]=src-field-name-off
    HookMethod   = 4,  // args[0]=klass, args[1]=method-name-off, args[2]=cookie
    ReadHookCount= 5,  // args[0]=cookie
    Eval         = 6,  // (placeholder for JS engine later)
    Shutdown     = 99,
};

struct alignas(16) AgentIpcBlock {
    uint32_t  magic;          // +0
    uint32_t  state;           // +4 (IpcState)
    uint32_t  request_id;      // +8
    uint32_t  pad0;            // +12
    uint32_t  cmd;             // +16 (CommandId)
    uint32_t  arg_count;       // +20
    uint64_t  args[16];        // +24 .. +151 (0x98 = 152 after args end)

    uint32_t  status;          // +152
    uint32_t  pad1;
    uint64_t  result[16];      // +160 .. +287

    uint32_t  msg_len;         // +288
    uint32_t  pad2;
    char      msg[AGENT_IPC_MSG_MAX];  // +296 .. +4391
};

static_assert(sizeof(AgentIpcBlock) < AGENT_IPC_SIZE,
              "IPC block exceeds shared region size");

} // namespace marrow
