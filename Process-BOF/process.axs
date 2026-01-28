var metadata = {
    name: "Process-BOF",
    description: "Situational awareness of processes, modules, and services"
};


var _cmd_findobj_module = ax.create_command("module", "Identify processes which have a certain module loaded", "findobj module clr.dll");
_cmd_findobj_module.addArgString("module", true);
_cmd_findobj_module.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let module = parsed_json["module"];

    let bof_params = ax.bof_pack("wstr", [module]);
    let bof_path = ax.script_dir() + "_bin/findmodule." + ax.arch(id) + ".o";
    let message = `Task: find process with module ${module}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});
var _cmd_findobj_prochandle = ax.create_command("prochandle", "Identify processes with a specific process handle in use", "findobj prochandle lsass.exe");
_cmd_findobj_prochandle.addArgString("proc", true);
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


var group_test = ax.create_commands_group("Process-BOF", [cmd_findobj, cmd_process]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);