#!/usr/bin/env python3
"""
extract_offsets.py — Kernel offset extractor for list_callbacks_bof.c
Usage: python3 extract_offsets.py <ntoskrnl.exe> <ntkrnlmp.pdb>

Extracts RVAs for:
  PspCreateProcessNotifyRoutine
  PspCreateThreadNotifyRoutine
  PspLoadImageNotifyRoutine
  PspCreateProcessNotifyRoutineCount
  PspCreateThreadNotifyRoutineCount
  PspLoadImageNotifyRoutineCount
  CallbackListHead
  PsProcessType
  PsThreadType

And prints a ready-to-paste KERNEL_OFFSETS entry for the BOF.
"""

import sys
import struct
import hashlib


def pe_sections(data):
    e_lfanew    = struct.unpack_from('<I', data, 0x3C)[0]
    num_secs    = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_size    = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_off     = e_lfanew + 24 + opt_size
    secs = []
    for i in range(num_secs):
        s     = sec_off + i * 40
        vaddr = struct.unpack_from('<I', data, s + 12)[0]
        vsize = struct.unpack_from('<I', data, s + 8)[0]
        raw   = struct.unpack_from('<I', data, s + 20)[0]
        secs.append((vaddr, vsize, raw))
    return secs

def rva2off(secs, rva):
    for va, vs, raw in secs:
        if va <= rva < va + vs:
            return rva - va + raw
    return None

def pe_build(data):
    """Extract build number from VS_FIXEDFILEINFO in resources."""

    return 0

def pe_build_from_version(data):
    """Scan for VS_FIXEDFILEINFO signature 0xFEEF04BD to get file version."""
    sig = b'\xbd\x04\xef\xfe'
    pos = data.find(sig)
    if pos == -1:
        return None

    ms = struct.unpack_from('<I', data, pos + 8)[0]
    ls = struct.unpack_from('<I', data, pos + 12)[0]
    major  = (ms >> 16) & 0xFFFF
    minor  = (ms >>  0) & 0xFFFF
    build  = (ls >> 16) & 0xFFFF
    patch  = (ls >>  0) & 0xFFFF
    return (major, minor, build, patch)

def pe_exports(data, secs, targets):
    """Return {name: rva} for target symbol names."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    opt_off  = e_lfanew + 24
    exp_rva  = struct.unpack_from('<I', data, opt_off + 112)[0]
    if exp_rva == 0:
        return {}
    exp_off   = rva2off(secs, exp_rva)
    num_names = struct.unpack_from('<I', data, exp_off + 24)[0]
    addr_rva  = struct.unpack_from('<I', data, exp_off + 28)[0]
    name_rva  = struct.unpack_from('<I', data, exp_off + 32)[0]
    ord_rva   = struct.unpack_from('<I', data, exp_off + 36)[0]
    addr_off  = rva2off(secs, addr_rva)
    name_off  = rva2off(secs, name_rva)
    ord_off   = rva2off(secs, ord_rva)
    results = {}
    for i in range(num_names):
        n_rva = struct.unpack_from('<I', data, name_off + i * 4)[0]
        n_off = rva2off(secs, n_rva)
        if n_off is None:
            continue
        end = data.index(b'\x00', n_off)
        sym = data[n_off:end].decode(errors='replace')
        if sym in targets:
            ordinal = struct.unpack_from('<H', data, ord_off + i * 2)[0]
            fn_rva  = struct.unpack_from('<I', data, addr_off + ordinal * 4)[0]
            results[sym] = fn_rva
    return results

def pdb_streams(data):
    page_size     = struct.unpack_from('<I', data, 32)[0]
    dir_size      = struct.unpack_from('<I', data, 44)[0]
    dir_map_pg    = struct.unpack_from('<I', data, 52)[0]
    num_dir_pages = (dir_size + page_size - 1) // page_size
    dir_pages     = [struct.unpack_from('<I', data, dir_map_pg * page_size + i * 4)[0]
                     for i in range(num_dir_pages)]
    dir_data      = b''.join(data[pg * page_size:(pg + 1) * page_size]
                             for pg in dir_pages)[:dir_size]
    num_streams   = struct.unpack_from('<I', dir_data, 0)[0]
    stream_sizes  = [struct.unpack_from('<I', dir_data, 4 + i * 4)[0]
                     for i in range(num_streams)]
    off = 4 + num_streams * 4
    streams = []
    for i in range(num_streams):
        sz = stream_sizes[i]
        if sz in (0xFFFFFFFF, 0):
            streams.append(b'')
            continue
        num_pgs = (sz + page_size - 1) // page_size
        pages   = [struct.unpack_from('<I', dir_data, off + j * 4)[0]
                   for j in range(num_pgs)]
        off    += num_pgs * 4
        sd      = b''.join(data[pg * page_size:(pg + 1) * page_size]
                           for pg in pages)[:sz]
        streams.append(sd)
    return streams

def pdb_guid(data):
    """Extract PDB GUID from stream 1 (PDB info stream)."""
    streams = pdb_streams(data)
    if len(streams) < 2:
        return None
    s = streams[1]
    if len(s) < 20:
        return None

    guid_bytes = s[8:24]
    age        = struct.unpack_from('<I', s, 24)[0]

    d1 = struct.unpack_from('<I',  guid_bytes, 0)[0]
    d2 = struct.unpack_from('<H',  guid_bytes, 4)[0]
    d3 = struct.unpack_from('<H',  guid_bytes, 6)[0]
    d4 = guid_bytes[8:16].hex().upper()
    return f"{d1:08X}{d2:04X}{d3:04X}{d4}{age}"

def pdb_pub32_rvas(pdb_data, pe_secs, targets):
    """
    Walk S_PUB32 records in the symbol stream and return {name: rva}.
    S_PUB32 layout (from record start):
      +0  reclen   (2) — length of record NOT including this field
      +2  rectype  (2) — 0x110E for S_PUB32
      +4  pubflags (4)
      +8  offset   (4) — section-relative offset
      +12 segment  (2) — 1-based PE section index
      +14 name     (NUL-terminated)
    """
    streams = pdb_streams(pdb_data)
    sym_stream = None

    anchor = targets[0].encode() + b'\x00'
    for s in streams:
        if s and anchor in s:
            sym_stream = s
            break
    if sym_stream is None:
        return {}

    target_set = {t.encode() for t in targets}
    results    = {}
    pos        = 0

    while pos + 4 <= len(sym_stream):
        reclen  = struct.unpack_from('<H', sym_stream, pos)[0]
        rectype = struct.unpack_from('<H', sym_stream, pos + 2)[0]
        if reclen == 0:
            break
        if rectype == 0x110E:  # S_PUB32
            sym_off = struct.unpack_from('<I', sym_stream, pos + 8)[0]
            sym_seg = struct.unpack_from('<H', sym_stream, pos + 12)[0]
            name_start = pos + 14
            name_end   = sym_stream.find(b'\x00', name_start)
            if name_end == -1:
                name_end = pos + reclen + 2
            name = sym_stream[name_start:name_end]
            if name in target_set:
                idx = sym_seg - 1
                if 0 <= idx < len(pe_secs):
                    sec_va = pe_secs[idx][0]
                    results[name.decode()] = sec_va + sym_off
        pos += reclen + 2

    return results

PDB_SYMBOLS = [
    'PspCreateProcessNotifyRoutine',
    'PspCreateThreadNotifyRoutine',
    'PspLoadImageNotifyRoutine',
    'PspCreateProcessNotifyRoutineCount',
    'PspCreateThreadNotifyRoutineCount',
    'PspLoadImageNotifyRoutineCount',
    'CallbackListHead',
    'EtwThreatIntProvRegHandle',
]

EXPORT_SYMBOLS = [
    'PsProcessType',
    'PsThreadType',
]

def pe_pdb_guid(data):
    """Extract PDB GUID directly from PE debug directory (no PDB needed)."""
    e_lfanew  = struct.unpack_from('<I', data, 0x3C)[0]
    opt_off   = e_lfanew + 24
    opt_size  = struct.unpack_from('<H', data, e_lfanew + 20)[0]

    magic     = struct.unpack_from('<H', data, opt_off)[0]
    dd_base   = opt_off + 112 if magic == 0x10B else opt_off + 112  # PE32
    if magic == 0x20B:  # PE32+
        dd_base = opt_off + 112
    dbg_rva   = struct.unpack_from('<I', data, dd_base + 6 * 8)[0]
    if dbg_rva == 0:
        return None
    secs    = pe_sections(data)
    dbg_off = rva2off(secs, dbg_rva)
    if dbg_off is None:
        return None

    for i in range(16):
        entry = dbg_off + i * 28
        if entry + 28 > len(data):
            break
        dbg_type    = struct.unpack_from('<I', data, entry + 12)[0]
        raw_data_sz = struct.unpack_from('<I', data, entry + 16)[0]
        raw_data_off= struct.unpack_from('<I', data, entry + 24)[0]
        if dbg_type == 2 and raw_data_sz >= 24:
            sig = data[raw_data_off:raw_data_off+4]
            if sig == b'RSDS':
                guid_b = data[raw_data_off+4:raw_data_off+20]
                age    = struct.unpack_from('<I', data, raw_data_off+20)[0]
                d1 = struct.unpack_from('<I',  guid_b, 0)[0]
                d2 = struct.unpack_from('<H',  guid_b, 4)[0]
                d3 = struct.unpack_from('<H',  guid_b, 6)[0]
                d4 = guid_b[8:16].hex().upper()
                return f"{d1:08X}{d2:04X}{d3:04X}{d4}{age}"
    return None


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"Usage:")
        print(f"  {sys.argv[0]} <ntoskrnl.exe>              — extract PDB GUID only")
        print(f"  {sys.argv[0]} <ntoskrnl.exe> <ntkrnlmp.pdb> — extract all offsets")
        sys.exit(1)

    exe_path = sys.argv[1]
    pdb_path = sys.argv[2] if len(sys.argv) == 3 else None

    with open(exe_path, 'rb') as f:
        exe_data = f.read()


    ver = pe_build_from_version(exe_data)
    if ver:
        build = ver[2]
        patch = ver[3]
        print(f"[*] File version : {ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}")
    else:
        build = 0
        patch = 0
        print("[!] Could not detect build number")

    sha256 = hashlib.sha256(exe_data).hexdigest()
    print(f"[*] SHA256        : {sha256}")

    guid = pe_pdb_guid(exe_data)
    if guid:
        print(f"[*] PDB GUID      : {guid}")
        print(f"")
        print(f"[*] Download PDB:")
        url = f"https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/{guid}/ntkrnlmp.pdb"
        print(f"    curl -L '{url}' -o ntkrnlmp_{build}.pdb")
    else:
        print("[!] Could not extract PDB GUID from debug directory")


    if pdb_path is None:
        sys.exit(0)

    with open(pdb_path, 'rb') as f:
        pdb_data = f.read()


    guid = pdb_guid(pdb_data)
    print()


    secs = pe_sections(exe_data)


    pdb_rvas = pdb_pub32_rvas(pdb_data, secs, PDB_SYMBOLS)


    exp_rvas = pe_exports(exe_data, secs, EXPORT_SYMBOLS)

    all_rvas = {**pdb_rvas, **exp_rvas}

    print()
    print("[*] Extracted RVAs:")
    all_symbols = PDB_SYMBOLS + EXPORT_SYMBOLS
    ok = True
    for sym in all_symbols:
        if sym in all_rvas:
            print(f"    {sym:<45} 0x{all_rvas[sym]:08X}")
        else:
            print(f"    {sym:<45} NOT FOUND")
            ok = False

    if not ok:
        print("\n[!] Some symbols missing — output may be incomplete")


    def rva(sym):
        v = all_rvas.get(sym, 0)
        return f"0x{v:08X}"

    entry = f"""
    /*
     * Build {build}.{patch}
     * SHA256 : {sha256}
     * PDB    : ntkrnlmp.pdb / {guid}
     */
    {{
        {build},
        {patch},
        {rva('PspCreateProcessNotifyRoutine')},  /* PspCreateProcessNotifyRoutine      */
        {rva('PspCreateThreadNotifyRoutine')},  /* PspCreateThreadNotifyRoutine       */
        {rva('PspLoadImageNotifyRoutine')},  /* PspLoadImageNotifyRoutine          */
        {rva('PspCreateProcessNotifyRoutineCount')},  /* PspCreateProcessNotifyRoutineCount */
        {rva('PspCreateThreadNotifyRoutineCount')},  /* PspCreateThreadNotifyRoutineCount  */
        {rva('PspLoadImageNotifyRoutineCount')},  /* PspLoadImageNotifyRoutineCount     */
        {rva('CallbackListHead')},  /* CallbackListHead                   */
        {rva('PsProcessType')},  /* PsProcessType                      */
        {rva('PsThreadType')},  /* PsThreadType                       */
        {rva('EtwThreatIntProvRegHandle')},  /* EtwThreatIntProvRegHandle: For the BOFs list_callbacks & remove_callback, this value is ignored, it is only valid for the ETW BOF. */
    }},"""

    print("\n" + "─" * 60)
    print("Paste into g_offsets[] in list_callbacks_bof.c:")
    print("─" * 60)
    print(entry)

if __name__ == '__main__':
    main()
