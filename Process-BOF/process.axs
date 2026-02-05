var metadata = {
    name: "Process-BOF",
    description: "Situational awareness of processes, modules, and services"
};


var _cmd_findobj_module = ax.create_command("module", "Identify processes which have a certain module loaded", "findobj module clr.dll");
_cmd_findobj_module.addArgString("module", true, "Module name to search for (e.g. clr.dll, amsi.dll, winhttp.dll)");
_cmd_findobj_module.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let module = parsed_json["module"];

    let bof_params = ax.bof_pack("wstr", [module]);
    let bof_path = ax.script_dir() + "_bin/findmodule." + ax.arch(id) + ".o";
    let message = `Task: find process with module ${module}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});
var _cmd_findobj_prochandle = ax.create_command("prochandle", "Identify processes with a specific process handle in use", "findobj prochandle lsass.exe");
_cmd_findobj_prochandle.addArgString("proc", true, "Process name to search handles for (e.g. lsass.exe)");
_cmd_findobj_prochandle.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let proc = parsed_json["proc"];

    let bof_params = ax.bof_pack("wstr", [proc]);
    let bof_path = ax.script_dir() + "_bin/findprochandle." + ax.arch(id) + ".o";
    let message = `Task: find processes with open handle ${proc}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});
var cmd_findobj = ax.create_command("findobj", "Enumerate processes for specific objects");
cmd_findobj.addSubCommands([_cmd_findobj_module, _cmd_findobj_prochandle]);


var _cmd_process_conn = ax.create_command("conn", "Shows detailed information from processes with established TCP and RDP connections", "process conn");
_cmd_process_conn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let bof_path = ax.script_dir() + "_bin/psc." + ax.arch(id) + ".o";
    let message = "Task: List process connection (BOF)";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, message);
});

var cmd_process = ax.create_command("process", "Shows detailed information from processes");
cmd_process.addSubCommands([_cmd_process_conn]);

var cmd_process_x = ax.create_command("process-x", "Shows detailed information from processes");
cmd_process_x.addSubCommands([_cmd_process_conn]);


var _cmd_procfreeze_freeze = ax.create_command("freeze", "Freeze a target process using PPL bypass via WerFaultSecure.exe");
_cmd_procfreeze_freeze.addArgInt("pid", true, "Process ID to freeze");
_cmd_procfreeze_freeze.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parseInt(parsed_json["pid"]);

    let bof_params = ax.bof_pack("int,int", [1, pid]);
    let bof_path = ax.script_dir() + "_bin/procfreeze." + ax.arch(id) + ".o";
    let message = `Task: Freeze process ${pid}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var _cmd_procfreeze_unfreeze = ax.create_command("unfreeze", "Unfreeze a previously frozen process");
_cmd_procfreeze_unfreeze.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let bof_params = ax.bof_pack("int,int", [2, 0]);
    let bof_path = ax.script_dir() + "_bin/procfreeze." + ax.arch(id) + ".o";
    let message = "Task: Unfreeze process";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_procfreeze = ax.create_command("procfreeze", "Process freeze/unfreeze using PPL bypass (WerFaultSecure.exe)");
cmd_procfreeze.addSubCommands([_cmd_procfreeze_freeze, _cmd_procfreeze_unfreeze]);


var group_process = ax.create_commands_group("Process-BOF", [cmd_findobj, cmd_process, cmd_procfreeze]);
ax.register_commands_group(group_process, ["beacon", "gopher"], ["windows"], []);

var group_process_x = ax.create_commands_group("Process-BOF-X", [cmd_findobj, cmd_process_x, cmd_procfreeze]);
ax.register_commands_group(group_process_x, ["kharon"], ["windows"], []);
