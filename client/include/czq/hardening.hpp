// hardening.hpp — binary-hardening seams (RFC §13). These are the *markers* the
// CI hardening step keys off; the actual transformation is applied by proprietary
// tools over the compiled binary (RFC §17 step 5), never at source level here.
//
//   * Windows  → VMProtect: wrap the boot-critical regions in CZQ_VM_BEGIN/END
//                (Ultra = virtualization). Enable string/import/memory protection
//                and debugger detection in the VMProtect project (RFC §13.1).
//   * mobile/Linux/mac → OLLVM: annotate the same functions with the OLLVM
//                attributes (control-flow flattening + bogus flow + string enc).
//
// When neither is configured the macros are no-ops so the code builds and runs
// unhardened for development/tests.
#pragma once

// ---- VMProtect (Windows) ------------------------------------------------------
#if defined(CZQ_USE_VMPROTECT)
#include "VMProtectSDK.h"
#define CZQ_VM_BEGIN(name) VMProtectBeginUltra(name)
#define CZQ_VM_BEGIN_MUTATE(name) VMProtectBeginMutation(name)
#define CZQ_VM_END() VMProtectEnd()
#define CZQ_IMAGE_CRC_OK() (VMProtectIsValidImageCRC() != 0)
#define CZQ_DEBUGGER_PRESENT() (VMProtectIsDebuggerPresent(true) != 0)
#else
#define CZQ_VM_BEGIN(name) ((void)0)
#define CZQ_VM_BEGIN_MUTATE(name) ((void)0)
#define CZQ_VM_END() ((void)0)
#define CZQ_IMAGE_CRC_OK() (true)      // unhardened dev build: assume intact
#define CZQ_DEBUGGER_PRESENT() (false) // unhardened dev build: assume clean
#endif

// ---- OLLVM (mobile/Linux/mac) -------------------------------------------------
// Apply to the boot-critical functions (RFC §13.2). No-op unless building with an
// OLLVM-enabled toolchain that recognizes these attributes.
#if defined(CZQ_USE_OLLVM)
#define CZQ_OBFUSCATE __attribute__((annotate("fla,sub,bcf")))
#else
#define CZQ_OBFUSCATE
#endif
