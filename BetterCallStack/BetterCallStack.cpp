#include <ida.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <Windows.h>
#include <DbgHelp.h>

BOOL CALLBACK MyReadProcessMemoryRoutine(
    HANDLE hProcess,
    DWORD64 lpBaseAddress,
    PVOID lpBuffer,
    DWORD nSize,
    LPDWORD lpNumberOfBytesRead
)
{
    auto nRead = get_bytes(lpBuffer, nSize, lpBaseAddress, 0, nullptr);
    if (nRead <= 0)
        return FALSE;

    *lpNumberOfBytesRead = nRead;

    return TRUE;
}

BOOL CALLBACK MySymbolCallback
(
    HANDLE hProcess,
    ULONG ActionCode,
    ULONG64 CallbackData,
    ULONG64 UserContext
)
{
    if (ActionCode == CBA_READ_MEMORY)
    {
        IMAGEHLP_CBA_READ_MEMORY * memRead = (IMAGEHLP_CBA_READ_MEMORY*)CallbackData;
        return MyReadProcessMemoryRoutine(hProcess, memRead->addr, memRead->buf, memRead->bytes, memRead->bytesread);
    }

    return FALSE;
}

#define MAX_CALLSTACK_FRAMES 100

void MakeCallStack(HANDLE hThread, CONTEXT & context, call_stack_t * callstack_info) 
{
    DWORD processId = GetProcessIdOfThread(hThread);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess)
        return;

    SymSetOptions(SYMOPT_DEFERRED_LOADS);
    CHAR system32Path[MAX_PATH] = {0};
    GetSystemDirectoryA(system32Path, sizeof(system32Path));
    qstrncat(system32Path, ";", sizeof(system32Path));
    SymInitialize(hProcess, system32Path, TRUE);
    SymRegisterCallback64(hProcess, &MySymbolCallback, 0);

    STACKFRAME64 stackFrame;
    memset(&stackFrame, 0, sizeof(stackFrame));
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrBStore.Mode = AddrModeFlat;

    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrFrame.Offset = context.Rbp;
    stackFrame.AddrBStore.Offset = context.Rbp;

    for (DWORD frame = 0; frame < MAX_CALLSTACK_FRAMES; frame++) 
    {

        bool is64 = getinf_flag(INF_LFLAGS, LFLG_64BIT);
        auto machine = IMAGE_FILE_MACHINE_AMD64;
        if (!is64)
            machine = IMAGE_FILE_MACHINE_I386;

        if (!StackWalk64(machine, hProcess, hThread, &stackFrame, &context, &MyReadProcessMemoryRoutine, SymFunctionTableAccess64, SymGetModuleBase64, NULL) || 
            !stackFrame.AddrPC.Offset)
            break;

        ea_t call_ea = stackFrame.AddrPC.Offset;
        ea_t func_ea = stackFrame.AddrFrame.Offset;  
        ea_t frame_pointer = stackFrame.AddrFrame.Offset;

        call_stack_info_t stack_info;
        stack_info.callea = call_ea;
        stack_info.funcea = getseg(call_ea)->start_ea;
        stack_info.fp = frame_pointer;
        stack_info.funcok = false;
        callstack_info->push_back(stack_info);
    }

    SymCleanup(hProcess);
    CloseHandle(hProcess);
}

struct idd_listener : event_listener_t
{
    virtual ssize_t idaapi on_event(ssize_t notification_code, va_list va) override
    {
        if (notification_code != debugger_t::ev_update_call_stack)
            return 0;

        ssize_t result = 0;
        if (get_process_state() != DSTATE_RUN)
        {
            thid_t tid = va_arg(va, thid_t);
            call_stack_t* trace = va_arg(va, call_stack_t*);

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
            if (hThread == NULL)
                return 0;

            CONTEXT context;
            memset(&context, 0, sizeof(CONTEXT));
            context.ContextFlags = CONTEXT_FULL;
            if (GetThreadContext(hThread, &context))
            {
                MakeCallStack(hThread, context, trace);
                result = 1;
            }

            CloseHandle(hThread);
        }
        return result;
    }
};

plugmod_t * idaapi init(void) 
{
    if (!is_debugger_on() || (ph.id != PLFM_386))
        return PLUGIN_SKIP;

    idd_listener* listener = new idd_listener();
    
    hook_event_listener(HT_IDD, listener, listener);
    return PLUGIN_KEEP;
}

static char comment[] = "IDA Stack Trace Plugin";
static char help[] = "This plugin collects and prints the call stack of the current thread.\n";
static char wanted_name[] = "IDA Stack Trace Plugin";
static char wanted_hotkey[] = "Alt-F12";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE,         // Plugin flags
  init,                // Initialize
  nullptr,                // Terminate. Optional. Called when the plugin is unloaded
  nullptr,                 // Main plugin function. Optional. Unused in this example
  comment,             // Comment. Can be NULL
  help,                // Help. Can be NULL
  wanted_name,         // Plugin name. Can be NULL
  wanted_hotkey        // Hotkey for the plugin. Can be NULL
};