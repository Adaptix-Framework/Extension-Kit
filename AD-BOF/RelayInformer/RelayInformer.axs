
let _cmd_informer_http = ax.create_command("http", "Inform on HTTP(S) service binding enforcement and HTTPS channel binding enforcement", "relay-informer http https://test.dom.local");
_cmd_informer_http.addArgString("url", true);
_cmd_informer_http.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let url = parsed_json["url"];

    let bof_params = ax.bof_pack("wstr", [url]);
    let bof_path = ax.script_dir() + "_bin/RelayInformer/http." + ax.arch(id) + ".o";
    let message = "Task: Inform on HTTP(S) service binding enforcement";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



let _cmd_informer_ldap = ax.create_command("ldap", "Inform on LDAP signing enforcement and LDAPS channel binding enforcement", "relay-informer ldap DC");
_cmd_informer_ldap.addArgString("host", true, "host or 'all'");
_cmd_informer_ldap.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr", [host]);
    let bof_path = ax.script_dir() + "_bin/RelayInformer/ldap." + ax.arch(id) + ".o";
    let message = "Task: Inform on LDAP signing enforcement";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



let _cmd_informer_mssql = ax.create_command("mssql", "Inform on MSSQL service binding and channel binding enforcement", "relay-informer mssql DB");
_cmd_informer_mssql.addArgString("host", true);
_cmd_informer_mssql.addArgInt("port", "", 1433);
_cmd_informer_mssql.addArgString("database", "", "master");
_cmd_informer_mssql.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];
    let port = parsed_json["port"];
    let database = parsed_json["database"];

    let bof_params = ax.bof_pack("cstr,int,cstr", [host, port, database]);
    let bof_path = ax.script_dir() + "_bin/RelayInformer/mssql." + ax.arch(id) + ".o";
    let message = "Task: Inform on MSSQL service binding and channel binding enforcement";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



let _cmd_informer_smb = ax.create_command("smb", "Inform on SMB2 signing enforcement", "relay-informer smb DC01");
_cmd_informer_smb.addArgString("host", true);
_cmd_informer_smb.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr", [host]);
    let bof_path = ax.script_dir() + "_bin/RelayInformer/smb." + ax.arch(id) + ".o";
    let message = "Task: Inform on SMB2 signing enforcement";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});


var cmd_informer = ax.create_command("relay-informer", "AD RelayInformer");
cmd_informer.addSubCommands([ _cmd_informer_http, _cmd_informer_ldap, _cmd_informer_mssql, _cmd_informer_smb ]);

var group_informer = ax.create_commands_group("AD RelayInformer", [cmd_informer]);
ax.register_commands_group(group_informer, ["beacon", "gopher", "kharon"], ["windows"], []);