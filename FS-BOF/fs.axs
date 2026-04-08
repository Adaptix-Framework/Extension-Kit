var metadata = {
    name: "FS-BOF",
    description: "Filesystem operations: dir, type, mkdir, copy, move, del, rmdir, pwd, cd",
    nosave: true
};

var cmd_dir = ax.create_command("dir", "Lists files in a specified directory. Supports wildcards (e.g. \"C:\\Windows\\S*\"). Optionally, it can perform a recursive list with the /s argument", "dir C:\\Users /s");
cmd_dir.addArgString("directory", "", ".\\");
cmd_dir.addArgBool("/s", "Recursive list");
cmd_dir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let recursive = 0;

    if(parsed_json["/s"]) { recursive = 1; }

    let bof_params = ax.bof_pack("wstr,int", [directory, recursive]);
    let bof_path = ax.script_dir() + "_bin/dir." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: dir");
});

var cmd_type = ax.create_command("type", "Display contents of a file to beacon output", "type C:\\path\\to\\file.txt");
cmd_type.addArgString("file", "", "");
cmd_type.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let file = parsed_json["file"];
    let bof_params = ax.bof_pack("wstr", [file]);
    let bof_path = ax.script_dir() + "_bin/type." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: type");
});

var cmd_mkdir = ax.create_command("mkdir", "Create a directory and all intermediate directories", "mkdir C:\\a\\b\\c");
cmd_mkdir.addArgString("directory", "", "");
cmd_mkdir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let bof_params = ax.bof_pack("wstr", [directory]);
    let bof_path = ax.script_dir() + "_bin/mkdir." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: mkdir");
});

var cmd_move = ax.create_command("move", "Move or rename files. Supports wildcards in source and UNC paths.", "move C:\\src\\*.log C:\\archive");
cmd_move.addArgString("source", "", "");
cmd_move.addArgString("destination", "", "");
cmd_move.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let source = parsed_json["source"];
    let dest   = parsed_json["destination"];
    let bof_params = ax.bof_pack("wstr,wstr", [source, dest]);
    let bof_path = ax.script_dir() + "_bin/move." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: move");
});

var cmd_del = ax.create_command("del", "Delete files at a specified path. Supports wildcards (e.g. \"C:\\temp\\*.tmp\"). File-only; directories are skipped.", "del C:\\temp\\file.txt");
cmd_del.addArgString("target", "", "");
cmd_del.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let bof_params = ax.bof_pack("wstr", [target]);
    let bof_path = ax.script_dir() + "_bin/del." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: del");
});

var cmd_copy = ax.create_command("copy", "Copy files to a destination path. Supports wildcards in source (e.g. \"C:\\src\\*.txt\") and UNC paths.", "copy C:\\src\\file.txt C:\\dest");
cmd_copy.addArgString("source", "", "");
cmd_copy.addArgString("destination", "", "");
cmd_copy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let source = parsed_json["source"];
    let dest   = parsed_json["destination"];
    let bof_params = ax.bof_pack("wstr,wstr", [source, dest]);
    let bof_path = ax.script_dir() + "_bin/copy." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: copy");
});

var cmd_pwd = ax.create_command("pwd", "Print the beacon's current working directory.", "pwd");
cmd_pwd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/pwd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" `, "BOF implementation: pwd");
});

var cmd_cd = ax.create_command("cd", "Change the beacon's current working directory. Supports relative paths (. and ..) and UNC paths.", "cd C:\\Windows\\System32");
cmd_cd.addArgString("directory", "", "");
cmd_cd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let bof_params = ax.bof_pack("wstr", [directory]);
    let bof_path = ax.script_dir() + "_bin/cd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: cd");
});

var cmd_rmdir = ax.create_command("rmdir", "Remove an empty directory at a specified path. Supports UNC paths.", "rmdir C:\\path\\to\\emptydir");
cmd_rmdir.addArgString("directory", "", "");
cmd_rmdir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let bof_params = ax.bof_pack("wstr", [directory]);
    let bof_path = ax.script_dir() + "_bin/rmdir." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: rmdir");
});

var group_fs = ax.create_commands_group("FS-BOF", [cmd_dir, cmd_type, cmd_mkdir, cmd_move, cmd_del, cmd_copy, cmd_rmdir, cmd_pwd, cmd_cd]);
ax.register_commands_group(group_fs, ["beacon", "gopher", "kharon"], ["windows"], []);
