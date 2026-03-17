#include "native_debug_detector.h"

#include <windows.h>
#include <winternl.h>
#include "../shield_codec.h"

typedef NTSTATUS(NTAPI *NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

namespace flutter_neo_shield {

// Encoded strings for ntdll access
static const std::string kNtdll = ShieldCodec::Decode({32,39,44,32,40,96,55,36,32});
static const std::string kNtQuery = ShieldCodec::Decode({0,39,25,57,33,60,42,1,34,34,33,33,37,45,48,39,60,38,28,54,33,48,45,63,55});

bool NativeDebugDetector::Check() {
  return CheckDebugPort() ||
         CheckDebugObjectHandle() ||
         CheckHardwareBreakpoints() ||
         CheckTimingAnomaly();
}

bool NativeDebugDetector::CheckDebugPort() {
  std::wstring wNtdll(kNtdll.begin(), kNtdll.end());
  HMODULE ntdll = ::GetModuleHandleW(wNtdll.c_str());
  if (!ntdll) return false;

  auto NtQueryInformationProcess =
      reinterpret_cast<NtQueryInformationProcessFn>(
          ::GetProcAddress(ntdll, kNtQuery.c_str()));
  if (!NtQueryInformationProcess) return false;

  DWORD_PTR debug_port = 0;
  NTSTATUS status = NtQueryInformationProcess(
      ::GetCurrentProcess(),
      static_cast<PROCESSINFOCLASS>(7),
      &debug_port,
      sizeof(debug_port),
      NULL);

  if (NT_SUCCESS(status) && debug_port != 0) {
    return true;
  }

  return false;
}

bool NativeDebugDetector::CheckDebugObjectHandle() {
  std::wstring wNtdll(kNtdll.begin(), kNtdll.end());
  HMODULE ntdll = ::GetModuleHandleW(wNtdll.c_str());
  if (!ntdll) return false;

  auto NtQueryInformationProcess =
      reinterpret_cast<NtQueryInformationProcessFn>(
          ::GetProcAddress(ntdll, kNtQuery.c_str()));
  if (!NtQueryInformationProcess) return false;

  HANDLE debug_object = NULL;
  NTSTATUS status = NtQueryInformationProcess(
      ::GetCurrentProcess(),
      static_cast<PROCESSINFOCLASS>(30),
      &debug_object,
      sizeof(debug_object),
      NULL);

  if (NT_SUCCESS(status)) {
    return true;
  }

  return false;
}

bool NativeDebugDetector::CheckHardwareBreakpoints() {
  CONTEXT ctx = {};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  if (::GetThreadContext(::GetCurrentThread(), &ctx)) {
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
      return true;
    }
  }

  return false;
}

bool NativeDebugDetector::CheckTimingAnomaly() {
  LARGE_INTEGER freq, start, end;
  ::QueryPerformanceFrequency(&freq);
  ::QueryPerformanceCounter(&start);

  volatile int sum = 0;
  for (int i = 0; i < 10000; i++) {
    sum += i;
  }

  ::QueryPerformanceCounter(&end);

  double elapsed_ms = static_cast<double>(end.QuadPart - start.QuadPart) *
                      1000.0 / static_cast<double>(freq.QuadPart);

  return elapsed_ms > 500.0;
}

}  // namespace flutter_neo_shield
