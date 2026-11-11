#!/usr/bin/env python3
"""Compile exact production OWN helpers with kernel/Mach stubs; no device access.

This checks helper control flow, not kernel primitives, retained proc identity,
iOS ABI or transport. Missing a native C compiler is an explicit SKIP.
"""
from pathlib import Path
import os
import re
import shlex
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
production = (root / "BaseBin/libroothider/src/dyld_patch.m").read_text(encoding="utf-8")
owned = production.split("/* OWN CHECKED REPAIR:", 1)[1]

def extract(name):
    match = re.search(r"static int " + re.escape(name) + r"\(", owned)
    if not match:
        raise AssertionError("production helper missing: " + name)
    start = match.start()
    opening = owned.index("{", match.end())
    depth = 0
    for index in range(opening, len(owned)):
        if owned[index] == "{":
            depth += 1
        elif owned[index] == "}":
            depth -= 1
            if depth == 0:
                return owned[start:index + 1] + "\n"
    raise AssertionError("unterminated production helper: " + name)

helpers = "\n".join(extract(name) for name in (
    "isolation_read_pointer", "isolation_cs_allow_invalid_checked", "isolation_task_set_dyld_info"))
assert "if (kwrite8(writeAddress, true) != 0) return -1;" in helpers
assert not re.search(r"\bcs_allow_invalid\(", helpers)
compiler = shlex.split(os.environ.get("CC", "cc"))
if not compiler or not shutil.which(compiler[0]):
    print("SKIP: exact production helpers extracted; native C compiler required for fixture execution")
    raise SystemExit(0)

preamble = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define UNSIGN_PTR(v) (v)
#define koffsetof(type, field) o_##type##_##field
#define DYLD_INFO_MAX_SEARCH_INDEX 200
#define TASK_DYLD_INFO 1
#define TASK_DYLD_INFO_COUNT 4
#define KERN_SUCCESS 0
static const uint64_t o_task_map = 0x100, o_vm_map_pmap = 0x100;
static uint64_t o_pmap_txm_address_space = 0x100, o_pmap_wx_allowed = 0x80;
static const uint64_t o_TXMAddressSpace_allowsInvalidCode = 0x80;
typedef unsigned mach_msg_type_number_t;
typedef int *task_info_t;
typedef struct { uint64_t all_image_info_addr, all_image_info_size; } task_dyld_info_data_t;
struct isolation_repair_guard { int pid; int pidversion; uint64_t kernel_task;
    bool (*cancelled)(void *); void *context; };
static int rh_isolation_pidversion(int pid) { (void)pid; return 7; }
static bool cancelled, arm64e = true;
static int reads, writes, cancel_read, fail_read, fail_write, cancel_write;
static bool cancelled_fn(void *unused) { (void)unused; return cancelled; }
static bool isolation_guard_allows_task(const struct isolation_repair_guard *guard)
{ return guard && !cancelled; }
static bool host_is_arm64e(void) { return arm64e; }
static uint64_t task_self(void) { return 0x1000; }
static int mach_task_self(void) { return 1; }
static int task_info(int task, int flavor, task_info_t buffer, mach_msg_type_number_t *count)
{
    (void)task; (void)flavor;
    task_dyld_info_data_t info = {0x8888, 0x40};
    memcpy(buffer, &info, sizeof(info)); *count = TASK_DYLD_INFO_COUNT;
    return KERN_SUCCESS;
}
static uint64_t kread64(uint64_t address)
{ return address == 0x1008 ? 0x8888 : address == 0x1010 ? 0x40 : 0; }
static int kreadbuf(uint64_t address, void *output, size_t size)
{
    reads++;
    if (reads == fail_read) return -1;
    if (size == 8) {
        uint64_t value = address == 0x2100 ? 0x3000 : address == 0x3100 ? 0x4000 :
                         address == 0x4100 ? 0x5000 : 0;
        if (!value) return -1;
        memcpy(output, &value, size);
    } else if (address == 0x2020 && size == 48) {
        const uint64_t values[6] = {1, 0, 0, 0, 1, 0};
        memcpy(output, values, size);
    } else return -1;
    if (reads == cancel_read) cancelled = true;
    return 0;
}
static int write_result(void)
{
    writes++;
    if (writes == fail_write) return -1;
    if (writes == cancel_write) cancelled = true;
    return 0;
}
static int kwrite8(uint64_t address, uint8_t value)
{ assert(address == (o_pmap_txm_address_space ? 0x5080 : 0x4080) && value == 1); return write_result(); }
static int kwritebuf(uint64_t address, const void *value, size_t size)
{ (void)value; assert(address == 0x2020 && size == 48); return write_result(); }
static int kwrite64(uint64_t address, uint64_t value)
{ (void)value; assert(address == 0x2008 || address == 0x2010); return write_result(); }
static void reset(void)
{ cancelled = false; arm64e = true; reads = writes = cancel_read = fail_read = fail_write = cancel_write = 0; }
'''

cases = r'''
int main(void)
{
    struct isolation_repair_guard guard = {0x11, 7, 0x2000, cancelled_fn, NULL};
    /* Both production pmap branches: cancellation in pointer reads prevents the
     * actual byte primitive; errors propagate rather than a success ACK. */
    for (int txm = 0; txm < 2; txm++) {
        o_pmap_txm_address_space = txm ? 0x100 : 0;
        reset(); assert(isolation_cs_allow_invalid_checked(&guard) == 0 && writes == 1);
        for (int point = 1; point <= (txm ? 3 : 2); point++) {
            reset(); cancel_read = point;
            assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 0);
            reset(); fail_read = point;
            assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 0);
        }
        reset(); fail_write = 1;
        assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 1);
        reset(); cancel_write = 1;
        assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 1);
        reset(); cancelled = true;
        assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 0);
    }
    reset(); arm64e = false;
    assert(isolation_cs_allow_invalid_checked(&guard) != 0 && writes == 0);
    reset(); assert(isolation_task_set_dyld_info(&guard, 0x9999, 0x40) == 0 && writes == 3);
    for (int point = 1; point <= 3; point++) {
        reset(); fail_write = point;
        assert(isolation_task_set_dyld_info(&guard, 0x9999, 0x40) != 0 && writes == point);
        reset(); cancel_write = point;
        assert(isolation_task_set_dyld_info(&guard, 0x9999, 0x40) != 0 && writes == point);
    }
    puts("PASS: extracted production cs/pmap + dyld-info helpers, mid-read cancellation, write errors and no subsequent writes");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="rh-checked-repair-") as directory:
    directory = Path(directory)
    source = directory / "fixture.c"
    executable = directory / ("fixture.exe" if os.name == "nt" else "fixture")
    source.write_text(preamble + helpers + cases, encoding="utf-8")
    subprocess.run(compiler + ["-std=c11", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
                   check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=10)
