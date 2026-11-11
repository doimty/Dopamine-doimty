#!/usr/bin/env python3
"""Owned source contracts only; not a Mach run or iOS link/runtime proof.

The parent owns the whole-repository official primitive-handoff fixture. This
check intentionally does not bless jbctl/boomerang/launchd bootstrap behavior.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
def source(path):
    return (root / path).read_text(encoding="utf-8")

def require(condition, message):
    if not condition:
        raise AssertionError(message)

client = source("BaseBin/libroothider/src/jailbreakd.c")
header = source("BaseBin/libroothider/src/jailbreakd.h")
main = source("BaseBin/jailbreakd/src/main.m")
server = source("BaseBin/jailbreakd/src/isolation_server.c")
mach = source("BaseBin/libroothider/src/app_isolation_mach.c")
protocol = source("BaseBin/libroothider/src/app_isolation_mach.h")
dyld = source("BaseBin/libroothider/src/dyld_patch.m")
domain = source("BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c")
ready = client.split("bool jbdIsolationHelperReady(void)", 1)[1].split("int jbdAppIsolationRepair", 1)[0]
repair = client.split("int jbdAppIsolationRepair", 1)[1].split("int jbdSpawnExecStart", 1)[0]
require("RH_ISOLATION_PING" in ready and "rh_isolation_mach_call" in ready, "readiness must PING")
require("return MACH_PORT_VALID" not in ready, "publication is not readiness")
require("RH_ISOLATION_PING_MS 100u" in protocol and "RH_ISOLATION_REPAIR_MS 1500u" in protocol,
        "fixed transport budgets")
require("xpc_pipe_routine" not in repair and "dispatch_async" not in repair, "repair has no unbounded XPC")
require("isolation_copy_service(true" in repair and "RH_ISOLATION_REPAIR_MS" in repair, "repair requires verified capability")
require("rh_isolation_pidversion(pid)" in repair and "proc_get_pidversion(pid)" not in repair,
        "systemhook must use userspace identity query")
require("isolationVerified = false" in client and "isolationGeneration == generation" in client,
        "cache retirement is generation-aware")
require("JBD_MSG_APP_ISOLATION" not in header and "1007" not in header, "no v1 XPC extension")
require("app_isolation_reply" not in client, "no obsolete reply interpreter")
require(main.index("jbclient_initialize_primitives()") < main.index('getenv("RESPAWN_REQUIRED")') <
        main.index("mach_port_t isolationPort"), "receiver after original primitive/respawn path")
require(main.index("jailbreakd_start_isolation_server();") < main.index("jbdCheckinWithIsolation(isolationPort)"),
        "arm before optional publication")
require("jbdIsolationHelperReady" not in main and "jbdIsolationHelperReady" not in server, "no synchronous pre-dispatch PING")
require("isolation-capability" in client and "isolation-capability" in domain, "existing checkin carries capability")
require("jbdRegisterIsolationHelper(callerToken, isolationCapability)" in domain, "candidate audited registration")
require("if (!MACH_PORT_VALID(isolation_port)) return jbclient_jailbreakd_checkin();" in client,
        "old client fallback stays official")
require(".args = {" not in domain, "official args are compound-literal pointers")
require(domain.count(".args = (jbserver_arg[])") == 10, "original pointer args inventory")
require("dispatch_async" not in server and "jbserver_xpc_send" not in server, "own serial Mach receiver")
make = source("BaseBin/systemhook/Makefile")
require("-lbsm" in make and "app_isolation_mach.c" in make, "standalone transport link")
require("size == (int)sizeof(info)" in mach and "== 56" in mach, "exact userspace proc layout")
require('"common.h"' not in mach and "libjailbreak" not in mach, "pure systemhook transport has no kernel dependency")
for path, text in (("mach", mach), ("client", client)):
    require(text.index("#include <bsm/audit.h>") < text.index("#include <bsm/libbsm.h>"),
            path + " audit accessor declaration order")
require(dyld.index("#include <bsm/audit.h>") < dyld.index("#include <libjailbreak/libjailbreak.h>"),
        "checked dyld audit header precedes shim")
require("audit_token_to_pid(audit_token_t" in source("BaseBin/_external/include/bsm/audit.h"), "repository accessor declaration")
require("MACH_SEND_TIMEOUT" in mach and "MACH_RCV_TIMEOUT" in mach, "bounded send and receive")
require("mach_port_mod_refs(mach_task_self(), reply_port, MACH_PORT_RIGHT_RECEIVE, -1)" in mach,
        "retire exact receive right")
for text in (mach, server, source("tests/app-isolation-mach.c")):
    require("mach_port_destroy(" not in text, "no SDK-deprecated right destructor")
require("reply->nonce != request.nonce" in mach, "nonce correlation")
require("audit_token_to_pidversion(trailer->msgh_audit) != helper_pidversion" in mach, "audit helper incarnation")
require("request->helper_pidversion == rh_isolation_pidversion(getpid())" in mach, "server validates helper before repair")
require("reply->helper_pidversion != helper_pidversion" in mach, "helper echo identity")
require("rh_isolation_request_cancelled" in server and "SIGCONT" not in server, "cancel without resume")
require("proc_fix_spinlock_strict_checked(request->pid, request->pidversion" in server, "checked repair only")
legacy, owned = dyld.split("/* OWN CHECKED REPAIR:", 1)
require("return proc_patch_dyld_internal(pid, false);" in legacy and
        "return proc_patch_dyld_internal(pid, true);" in legacy, "stock legacy signatures and routing")
require("assert((stockDyldInfo=loadDyldInfo" in legacy and "assert((patchedDyldInfo=loadDyldInfo" in legacy,
        "legacy initialization behavior")
require("isolation_guard_allows_task" not in legacy, "no checked behavior inserted into legacy helpers")
require("audit_token_to_pidversion(token) != expected_pidversion" in owned, "audit fixed Mach task")
require("current != guard->proc" in owned and "proc_task(current) != guard->kernel_task" in owned,
        "proc/task revalidation, not a kernel pin")
require("cooperatively" in dyld and "narrow race" in owned and "already executing kernel" in owned,
        "explicit residual race/in-flight primitive limitation")
require("proc_rele(" not in owned and "proc_fix_spinlock_strict(pid_t" not in owned, "no fictitious retain or unchecked own repair")
require(not re.search(r"\bcs_allow_invalid\(", owned), "own repair must not call unchecked legacy cs/pmap helper")
require("isolation_cs_allow_invalid_checked(&guard)" in owned and "if (kwrite8(writeAddress, true) != 0)" in owned,
        "checked cs/pmap performs and propagates the actual byte write")
require("if (kreadbuf(address, &raw, sizeof(raw)) != 0)" in owned, "checked pointer reads propagate errors")
require("discard_pseudo_send_rights(&request.header, transport)" in mach and
        "MACH_MSGH_BITS_LOCAL(header->msgh_bits) == MACH_MSG_TYPE_PORT_SEND_ONCE" in mach,
        "pseudo-copyout send failure cleans only returned header rights")
fixture = source("tests/app-isolation-mach.c")
require(".mpl_qlimit = 1" in fixture and "current_refs == start_refs" in fixture and
        "name_count() == full_queue_names" in fixture, "full-queue send timeout right/uref coverage")
# Every owned remote mutation is immediately preceded by a guard (not just once at entry).
lines = owned.splitlines()
mutations = 0
for index, line in enumerate(lines):
    if re.search(r"\b(?:vm_protect|vm_copy|vm_write|vm_remap|vm_deallocate|kwrite8|kwritebuf|kwrite64)\(", line):
        if "mach_task_self()" in line:
            continue
        require(index > 0 and "isolation_guard_allows_task" in lines[index - 1],
                "unguarded owned mutation: " + line.strip())
        if re.search(r"\bkwrite(?:8|buf|64)\(", line):
            require("if (kwrite" in line and "!= 0) return -1;" in line,
                    "owned kernel write ignores error: " + line.strip())
        mutations += 1
require(mutations == 13, "reviewed owned remote mutation inventory")
runner = source("scripts/test-app-isolation-mach.sh")
require("start_new_session=True" in runner and "timeout=30" in runner and "os.killpg" in runner,
        "30-second owned process group cleanup")
require("--sdk iphoneos clang" in runner and "for arch in arm64 arm64e" in runner and
        "-fsyntax-only" in runner and "-dynamiclib" in runner and "-undefined,error" in runner,
        "both iOS architecture syntax and real link probes, not host-pass substitution")
print("PASS: owned Mach v2/checkin/cancellation/legacy/source wiring contracts (static only)")
