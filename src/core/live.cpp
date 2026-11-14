#include "live.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#include "logger.h"
#include "state.h"
#include "../mem/safe_memory.h"
#include "../game/offsets.h"
#include "../game/player.h"
#include "../game/inventory.h"

namespace trinity::game
{
    // friendly.cpp: remaining apply-thunk calls to trace.
    extern volatile long g_applyTraceLeft;
}

namespace trinity::live
{
    using namespace ::trinity::game;

    namespace
    {
        char g_inPath[MAX_PATH]{};
        char g_outPath[MAX_PATH]{};

        struct Out
        {
            std::string s;
            void f(const char* fmt, ...)
            {
                char buf[1024];
                va_list ap;
                va_start(ap, fmt);
                vsnprintf(buf, sizeof(buf), fmt, ap);
                va_end(ap);
                s += buf;
            }
        };

        uintptr_t Hex(const char* t)
        {
            return static_cast<uintptr_t>(_strtoui64(t, nullptr, 16));
        }

        // MSVC x64 RTTI: vtable[-1] -> CompleteObjectLocator; COL+0x0C is the
        // TypeDescriptor RVA, COL+0x14 the COL's own RVA (gives the image base).
        bool RttiName(uintptr_t obj, char* out, size_t n)
        {
            out[0] = 0;
            uintptr_t vt = 0, col = 0;
            if (!mem::ReadPtr(obj, &vt) || !mem::ReadPtr(vt - 8, &col)) return false;
            uint32_t sig = 0, tdRva = 0, selfRva = 0;
            if (!mem::Read32(col, &sig) || sig != 1) return false;
            if (!mem::Read32(col + 0x0C, &tdRva) || !mem::Read32(col + 0x14, &selfRva)) return false;
            const uintptr_t base = col - selfRva;
            return mem::ReadCString(base + tdRva + 0x10, out, n) && out[0];
        }

        void CmdRead(Out& o, uintptr_t a, size_t len)
        {
            if (len > 0x800) len = 0x800;
            for (size_t off = 0; off < len; off += 16)
            {
                uint8_t b[16]{};
                const size_t n = (len - off) < 16 ? (len - off) : 16;
                if (!mem::ReadBytes(a + off, b, n)) { o.f("  %016llx: <unreadable>\n", (unsigned long long)(a + off)); break; }
                o.f("  %016llx:", (unsigned long long)(a + off));
                for (size_t i = 0; i < n; ++i) o.f(" %02X", b[i]);
                o.f("\n");
            }
        }

        void CmdSlots(Out& o, uintptr_t a, uintptr_t from, uintptr_t to)
        {
            if (to - from > 0x2000) to = from + 0x2000;
            for (uintptr_t off = from & ~uintptr_t(7); off < to; off += 8)
            {
                uintptr_t v = 0;
                if (!mem::ReadPtr(a + off, &v)) { o.f("  +%04llx <unreadable>\n", (unsigned long long)off); break; }
                if (v < kMinPointer) continue;
                char name[160];
                if (RttiName(v, name, sizeof(name)))
                    o.f("  +%04llx -> %016llx  %s\n", (unsigned long long)off, (unsigned long long)v, name);
            }
        }

        void WalkTrust(Out& o, const char* label, uintptr_t owner)
        {
            uintptr_t sub = 0, comp = 0, back = 0, entries = 0;
            uint32_t size = 0;
            o.f("  %s owner=%016llx\n", label, (unsigned long long)owner);
            if (owner < kMinPointer) return;
            if (!mem::ReadPtr(owner + kOff_Owner_Actor, &sub) || sub < kMinPointer) { o.f("    no actor at +%llx\n", (unsigned long long)kOff_Owner_Actor); return; }
            if (!mem::ReadPtr(sub + kOff_Sub_FriendlyComp, &comp) || comp < kMinPointer) { o.f("    actor %016llx: no comp at +%llx\n", (unsigned long long)sub, (unsigned long long)kOff_Sub_FriendlyComp); return; }
            char name[160];
            RttiName(comp, name, sizeof(name));
            mem::ReadPtr(comp + 0x08, &back);
            mem::Read32(comp + kOff_FriendlyComp_Size, &size);
            mem::ReadPtr(comp + kOff_FriendlyComp_Entries, &entries);
            o.f("    actor=%016llx comp=%016llx (%s) back==owner=%d size=%u entries=%016llx\n",
                (unsigned long long)sub, (unsigned long long)comp, name, back == owner ? 1 : 0, size,
                (unsigned long long)entries);
            if (size > 4096 || entries < kMinPointer) return;
            for (uint32_t i = 0; i < size; ++i)
            {
                uintptr_t e = 0, rec = 0;
                uint64_t key = 0;
                int64_t val = 0;
                if (!mem::ReadPtr(entries + i * 8ull, &e) || e < kMinPointer) continue;
                mem::Read64(e, &key);
                if (!mem::ReadPtr(e + kOff_FriendlyEntry_Record, &rec) || rec < kMinPointer) continue;
                mem::Read64(rec + kOff_FriendlyRecord_Value, &val);
                o.f("    [%3u] key=%013llx rec=%016llx val=%lld\n", i, (unsigned long long)key,
                    (unsigned long long)rec, (long long)val);
            }
        }

        // Exception-safe write that also works on code pages (read-only +
        // executable): temporarily lifts the protection, writes, restores it
        // and flushes the instruction cache. Used for live, temporary fixes.
        bool HostWrite(uintptr_t a, const void* in, size_t n)
        {
            if (!mem::IsValidUserPtr(a) || !in || !n) return false;
            DWORD old = 0;
            const bool reprotect = VirtualProtect(reinterpret_cast<void*>(a), n, PAGE_EXECUTE_READWRITE, &old) != 0;
            bool ok = false;
            __try { memcpy(reinterpret_cast<void*>(a), in, n); ok = true; }
            __except (EXCEPTION_EXECUTE_HANDLER) { ok = false; }
            if (reprotect)
            {
                DWORD tmp = 0;
                VirtualProtect(reinterpret_cast<void*>(a), n, old, &tmp);
                FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(a), n);
            }
            return ok;
        }

        HMODULE g_self = nullptr;

        // ---- hardware write watchpoint (Dr0) --------------------------------
        // `watch <addr>` arms Dr0 as an 8-byte write watchpoint on every thread
        // of the process; the vectored handler records the writing instruction
        // and a few return-address candidates from the stack into a ring that
        // the worker flushes to Trinity_live_out.txt. `unwatch` disarms.
        struct WatchHit { uintptr_t rip, rsp, rcx, rdx, r8, r9, rdi, rsi, rbx; uintptr_t stack[12]; uintptr_t frames[20]; int nframes; DWORD tid; };
        volatile bool g_watchExec = false;
        WatchHit g_hits[32]{};
        volatile long g_hitCount = 0;
        long g_hitsPrinted = 0; // hits already written out; reset on every re-arm
        volatile uintptr_t g_watchAddr = 0;
        PVOID g_veh = nullptr;

        LONG CALLBACK WatchHandler(EXCEPTION_POINTERS* ep)
        {
            if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
            CONTEXT* c = ep->ContextRecord;
            if (!(c->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH; // not our Dr0
            c->Dr6 = 0;
            const long i = InterlockedIncrement(&g_hitCount) - 1;
            if (i < 32)
            {
                WatchHit& h = g_hits[i];
                h.rip = c->Rip; h.rsp = c->Rsp; h.rcx = c->Rcx; h.rdx = c->Rdx; h.r8 = c->R8; h.r9 = c->R9;
                h.tid = GetCurrentThreadId();
                h.rdi = c->Rdi; h.rsi = c->Rsi; h.rbx = c->Rbx;
                for (int k = 0; k < 12; ++k)
                    mem::ReadPtr(c->Rsp + k * 8ull, &h.stack[k]);
                // Real call stack via .pdata unwind (game ships full .pdata).
                CONTEXT u = *c;
                h.nframes = 0;
                for (int f = 0; f < 20 && u.Rip; ++f)
                {
                    h.frames[h.nframes++] = u.Rip;
                    DWORD64 imgBase = 0;
                    PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(u.Rip, &imgBase, nullptr);
                    if (!fn)
                    {
                        uintptr_t ret = 0;
                        if (!mem::ReadPtr(u.Rsp, &ret)) break;
                        u.Rip = ret; u.Rsp += 8;
                        continue;
                    }
                    PVOID hd = nullptr; DWORD64 est = 0;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgBase, u.Rip, fn, &u, &hd, &est, nullptr);
                }
            }
            else c->Dr7 &= ~1ull; // ring full: stop trapping on this thread (avoids stutter on hot code)
            if (g_watchExec) c->EFlags |= 0x10000; // RF: resume past the execute breakpoint
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        int ArmAllThreads(uintptr_t addr, bool exec = false, bool rw = false)
        {
            const DWORD self = GetCurrentThreadId();
            const DWORD pid = GetCurrentProcessId();
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == INVALID_HANDLE_VALUE) return 0;
            int armed = 0;
            THREADENTRY32 te{ sizeof(te) };
            for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
            {
                if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
                HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!t) continue;
                if (SuspendThread(t) != static_cast<DWORD>(-1))
                {
                    CONTEXT c{};
                    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(t, &c))
                    {
                        c.Dr0 = addr;
                        // Dr7: L0=1, RW0=01 (write), LEN0=10 (8 bytes); clear when addr==0
                        c.Dr7 = addr ? ((c.Dr7 & ~0xF0003ull) | 0x1ull | (exec ? 0ull : (((rw ? 0x3ull : 0x1ull) << 16) | (0x2ull << 18))))
                                     : (c.Dr7 & ~0xF0003ull);
                        c.Dr6 = 0;
                        if (SetThreadContext(t, &c)) ++armed;
                    }
                    ResumeThread(t);
                }
                CloseHandle(t);
            }
            CloseHandle(snap);
            return armed;
        }

        void FlushWatchHits(Out& o);
        bool SafeDispatch(const std::vector<std::string>& tok, Out& o);

        void Execute(const std::string& line, Out& o)
        {
            std::vector<std::string> tok;
            {
                size_t i = 0;
                while (i < line.size())
                {
                    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
                    size_t j = i;
                    while (j < line.size() && line[j] != ' ' && line[j] != '\t') ++j;
                    if (j > i) tok.emplace_back(line.substr(i, j - i));
                    i = j;
                }
            }
            if (tok.empty() || tok[0][0] == '#') return;
            o.f("> %s\n", line.c_str());
            if (!SafeDispatch(tok, o))
                o.f("  <exception while executing>\n");
        }

        void Dispatch(const std::vector<std::string>& tok, Out& o)
        {
            const std::string& c = tok[0];
            {
                if (c == "owner")
                {
                    o.f("  client=%016llx server=%016llx\n",
                        (unsigned long long)game::Player::GetControlledOwner(),
                        (unsigned long long)game::Inventory::ServerCharacterAddr());
                }
                else if (c == "read" && tok.size() >= 3)
                    CmdRead(o, Hex(tok[1].c_str()), Hex(tok[2].c_str()));
                else if (c == "chain" && tok.size() >= 2)
                {
                    uintptr_t p = Hex(tok[1].c_str());
                    o.f("  start %016llx\n", (unsigned long long)p);
                    for (size_t k = 2; k < tok.size(); ++k)
                    {
                        const uintptr_t off = Hex(tok[k].c_str());
                        uintptr_t v = 0;
                        if (!mem::ReadPtr(p + off, &v)) { o.f("  [+%llx] unreadable\n", (unsigned long long)off); break; }
                        char name[160];
                        RttiName(v, name, sizeof(name));
                        o.f("  [%016llx+%llx] = %016llx %s\n", (unsigned long long)p, (unsigned long long)off,
                            (unsigned long long)v, name);
                        p = v;
                    }
                }
                else if (c == "rtti" && tok.size() >= 2)
                {
                    char name[160];
                    const uintptr_t a = Hex(tok[1].c_str());
                    o.f("  %016llx: %s\n", (unsigned long long)a, RttiName(a, name, sizeof(name)) ? name : "<no rtti>");
                }
                else if (c == "slots" && tok.size() >= 4)
                    CmdSlots(o, Hex(tok[1].c_str()), Hex(tok[2].c_str()), Hex(tok[3].c_str()));
                else if (c == "trust")
                {
                    WalkTrust(o, "client", game::Player::GetControlledOwner());
                    WalkTrust(o, "server", game::Inventory::ServerCharacterAddr());
                }
                else if (c == "base")
                {
                    // Load addresses, to turn map-file / IDA offsets into live addresses.
                    o.f("  game    %016llx\n", (unsigned long long)reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)));
                    o.f("  trinity %016llx (map preferred base 0000000180000000)\n",
                        (unsigned long long)reinterpret_cast<uintptr_t>(g_self));
                }
                else if ((c == "watch" || c == "watchx" || c == "watchr") && tok.size() >= 2)
                {
                    const bool exec = c == "watchx";
                    const bool rw = c == "watchr"; // read OR write (RW=11)
                    const uintptr_t a = exec ? Hex(tok[1].c_str()) : (Hex(tok[1].c_str()) & ~uintptr_t(7));
                    if (!g_veh) g_veh = AddVectoredExceptionHandler(1, &WatchHandler);
                    InterlockedExchange(&g_hitCount, 0);
                    g_hitsPrinted = 0;
                    g_watchExec = exec;
                    g_watchAddr = a;
                    const int n = ArmAllThreads(a, exec, rw);
                    o.f("  %s breakpoint on %016llx armed on %d thread(s) - hits are appended here as they happen\n",
                        exec ? "execute" : rw ? "read/write" : "write", (unsigned long long)a, n);
                    LOG_INFO("live: write watchpoint @ %p on %d thread(s)", reinterpret_cast<void*>(a), n);
                }
                else if (c == "unwatch")
                {
                    g_watchAddr = 0;
                    const int n = ArmAllThreads(0);
                    InterlockedExchange(&g_hitCount, 0);
                    g_hitsPrinted = 0;
                    o.f("  watchpoint cleared on %d thread(s)\n", n);
                }
                else if (c == "write" && tok.size() >= 3)
                {
                    // write <addr> <byte> <byte> ...   (hex bytes) - temporary live fix
                    const uintptr_t a = Hex(tok[1].c_str());
                    std::vector<uint8_t> bytes;
                    for (size_t k = 2; k < tok.size(); ++k)
                        bytes.push_back(static_cast<uint8_t>(Hex(tok[k].c_str())));
                    uint8_t before[64]{};
                    const size_t n = bytes.size() < sizeof(before) ? bytes.size() : sizeof(before);
                    mem::ReadBytes(a, before, n);
                    const bool ok = HostWrite(a, bytes.data(), n);
                    o.f("  %s %zu byte(s) @ %016llx (was:", ok ? "wrote" : "FAILED", n, (unsigned long long)a);
                    for (size_t i = 0; i < n; ++i) o.f(" %02X", before[i]);
                    o.f(")\n");
                    LOG_INFO("live: write %zu byte(s) @ %p %s", n, reinterpret_cast<void*>(a), ok ? "ok" : "failed");
                }
                else if (c == "write64" && tok.size() >= 3)
                {
                    // write64 <addr> <decimal value> - e.g. set one trust value
                    const uintptr_t a = Hex(tok[1].c_str());
                    const int64_t v = _strtoi64(tok[2].c_str(), nullptr, 10);
                    int64_t before = 0;
                    mem::Read64(a, &before);
                    const bool ok = HostWrite(a, &v, sizeof(v));
                    o.f("  %s @ %016llx: %lld -> %lld\n", ok ? "wrote" : "FAILED", (unsigned long long)a,
                        (long long)before, (long long)v);
                    LOG_INFO("live: write64 @ %p %lld -> %lld %s", reinterpret_cast<void*>(a),
                             (long long)before, (long long)v, ok ? "ok" : "failed");
                }
                else if (c == "trace" && tok.size() >= 2)
                {
                    const long n = static_cast<long>(strtol(tok[1].c_str(), nullptr, 10));
                    InterlockedExchange(&game::g_applyTraceLeft, n);
                    o.f("  apply trace armed for %ld call(s) - results go to Trinity.log\n", n);
                }
                else
                    o.f("  unknown command or missing arguments\n");
            }
        }

        // SEH wrapper with no destructible locals (MSVC C2712).
        bool SafeDispatch(const std::vector<std::string>& tok, Out& o)
        {
            __try { Dispatch(tok, o); return true; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
        }

        void FlushWatchHits(Out& o)
        {
            const long total = g_hitCount;
            if (total < g_hitsPrinted) g_hitsPrinted = 0; // re-armed
            const uintptr_t game = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
            for (; g_hitsPrinted < total && g_hitsPrinted < 32; ++g_hitsPrinted)
            {
                const WatchHit& h = g_hits[g_hitsPrinted];
                int64_t now = 0;
                if (!g_watchExec) mem::Read64(g_watchAddr, &now);
                o.f("  HIT #%ld tid=%lu rip=%016llx (game+%llx) value now=%lld\n", g_hitsPrinted + 1, h.tid,
                    (unsigned long long)h.rip, (unsigned long long)(h.rip - game), (long long)now);
                o.f("    rcx=%016llx rdx=%016llx r8=%016llx r9=%016llx rsp=%016llx\n",
                    (unsigned long long)h.rcx, (unsigned long long)h.rdx, (unsigned long long)h.r8,
                    (unsigned long long)h.r9, (unsigned long long)h.rsp);
                o.f("    stack:");
                for (int k = 0; k < 12; ++k)
                {
                    const uintptr_t v = h.stack[k];
                    if (v >= game && v < game + 0x14000000) o.f(" game+%llx", (unsigned long long)(v - game));
                    else o.f(" %llx", (unsigned long long)v);
                }
                o.f("\n    rdi=%016llx rsi=%016llx rbx=%016llx\n", (unsigned long long)h.rdi,
                    (unsigned long long)h.rsi, (unsigned long long)h.rbx);
                o.f("    callstack:");
                for (int f = 0; f < h.nframes; ++f)
                {
                    const uintptr_t v = h.frames[f];
                    if (v >= game && v < game + 0x20000000) o.f(" game+%llx", (unsigned long long)(v - game));
                    else o.f(" %llx", (unsigned long long)v);
                }
                o.f("\n");
            }
        }

        volatile bool g_stop = false;
        HANDLE g_worker = nullptr;

        DWORD WINAPI Worker(LPVOID)
        {
            while (!g_stop)
            {
                Sleep(250);
                if (g_hitCount > g_hitsPrinted && g_hitsPrinted < 32)
                {
                    Out ho;
                    ho.f("=== watch hits\n");
                    FlushWatchHits(ho);
                    FILE* w = nullptr;
                    if (fopen_s(&w, g_outPath, "ab") == 0 && w)
                    {
                        fwrite(ho.s.data(), 1, ho.s.size(), w);
                        fclose(w);
                    }
                }
                FILE* f = nullptr;
                if (fopen_s(&f, g_inPath, "rb") != 0 || !f) continue;
                std::string all;
                char buf[4096];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), f)) > 0) all.append(buf, n);
                fclose(f);
                DeleteFileA(g_inPath);

                Out o;
                SYSTEMTIME t;
                GetLocalTime(&t);
                o.f("=== %02u:%02u:%02u.%03u\n", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
                size_t s = 0;
                while (s <= all.size())
                {
                    size_t e = all.find('\n', s);
                    if (e == std::string::npos) e = all.size();
                    std::string line = all.substr(s, e - s);
                    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
                    if (!line.empty()) Execute(line, o);
                    s = e + 1;
                }
                FILE* w = nullptr;
                if (fopen_s(&w, g_outPath, "ab") == 0 && w)
                {
                    fwrite(o.s.data(), 1, o.s.size(), w);
                    fclose(w);
                }
            }
            return 0;
        }
    }

    void Start(HMODULE self)
    {
        g_self = self;
        char dir[MAX_PATH]{};
        if (!GetModuleFileNameA(self, dir, MAX_PATH)) return;
        char* slash = strrchr(dir, '\\');
        if (slash) *slash = 0;
        snprintf(g_inPath, sizeof(g_inPath), "%s\\Trinity_live.txt", dir);
        snprintf(g_outPath, sizeof(g_outPath), "%s\\Trinity_live_out.txt", dir);
        DeleteFileA(g_inPath);

        g_stop = false;
        if (HANDLE h = CreateThread(nullptr, 0, &Worker, nullptr, 0, nullptr))
        {
            g_worker = h;
            LOG_INFO("live: diagnostics channel on - commands in Trinity_live.txt, results in Trinity_live_out.txt.");
        }
    }

    void Stop()
    {
        g_stop = true;
        if (g_worker)
        {
            WaitForSingleObject(g_worker, 5000);
            CloseHandle(g_worker);
            g_worker = nullptr;
        }
        if (g_watchAddr) { g_watchAddr = 0; ArmAllThreads(0); }
        if (g_veh) { RemoveVectoredExceptionHandler(g_veh); g_veh = nullptr; }
    }
}
