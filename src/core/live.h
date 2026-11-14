#pragma once
#include <Windows.h>

// Live diagnostics channel. A background thread polls Trinity_live.txt (next to
// Trinity.asi) every 250 ms; each line is a read-only command whose result is
// appended to Trinity_live_out.txt. Lets a session be investigated while the
// game keeps running instead of a rebuild + restart per question.
//
// Commands (addresses/offsets in hex, with or without 0x):
//   owner                      controlled client owner + server character
//   read  <addr> <len>         hex dump (len <= 0x800)
//   chain <addr> <off>...      follow [ptr+off] hops, print each step
//   rtti  <addr>               MSVC RTTI class name of the object at addr
//   slots <addr> <from> <to>   every pointer slot in [addr+from, addr+to)
//                              with the RTTI name of what it points to
//   trust                      walk the client + server friendly ledgers
//   trace <n>                  log the next n trust-apply calls
//   base                       load addresses of the game and Trinity.asi
//   write <addr> <b> <b>...    write hex bytes (works on code pages too) -
//                              a temporary live fix, gone on restart
//   write64 <addr> <decimal>   write one 64-bit value
namespace trinity::live
{
    void Start(HMODULE self);
}
