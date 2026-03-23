var metadata = {
    name: "SAL-BOF",
    description: "Situation Awareness Local BOFs"
};


var cmd_arp = ax.create_command("arp", "List ARP table", "arp");
cmd_arp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/arp." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: arp");
});

var cmd_cacls = ax.create_command("cacls", "List user permissions for the specified file or directory, wildcards supported", "cacls C:\\test.txt");
cmd_cacls.addArgString("path", true);
cmd_cacls.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let path = parsed_json["path"];

    let bof_params = ax.bof_pack("wstr", [path]);
    let bof_path = ax.script_dir() + "_bin/cacls." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: cacls");
});

var cmd_dir = ax.create_command("dir", "Lists files in a specified directory. Supports wildcards (e.g. \"C:\\Windows\\S*\"). Optionally, it can perform a recursive list with the /s argument", "dir C:\\Users /s");
cmd_dir.addArgString("directory", "", ".\\");
cmd_dir.addArgBool("/s", "Recursive list");
cmd_dir.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directory = parsed_json["directory"];
    let recursive = 0;

    if(parsed_json["/s"]) { recursive = 1; }

    let bof_params = ax.bof_pack("wstr,int", [directory, recursive]);
    let bof_path = ax.script_dir() + "_bin/dir." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: dir");
});

var cmd_env = ax.create_command("env", "List process environment variables", "env");
cmd_env.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/env." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "List process environment variables (BOF)");
});

var cmd_ipconfig = ax.create_command("ipconfig", "List IPv4 address, hostname, and DNS server", "ipconfig");
cmd_ipconfig.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/ipconfig." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: ipconfig");
});

var cmd_listdns = ax.create_command("listdns", "List DNS cache entries. Attempt to query and resolve each", "listdns");
cmd_listdns.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/listdns." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: ipconfig /displaydns");
});

var cmd_netstat = ax.create_command("netstat", "Executes the netstat command to display network connections", "netstat");
cmd_netstat.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/netstat." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: netstat");
});

var cmd_nslookup = ax.create_command("nslookup", "Make a DNS query", "nslookup google.com -s 8.8.8.8 -t A");
cmd_nslookup.addArgString("domain", true);
cmd_nslookup.addArgFlagString("-s", "server", "DNS server is the server you want to query", "");
cmd_nslookup.addArgFlagString("-t", "type", "Record type is something like A, AAAA, or ANY", "A");
cmd_nslookup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let domain = parsed_json["domain"];
    let server = parsed_json["server"];
    let type   = parsed_json["type"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [domain, type, server]);
    let bof_path = ax.script_dir() + "_bin/nslookup." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: nslookup");
});

var _cmd_privcheck_alwayselevated = ax.create_command("alwayselevated", "Checks if Always Install Elevated is enabled using the registry", "privcheck alwayselevated");
_cmd_privcheck_alwayselevated.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/alwayselevated." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks AlwaysInstallElevated");
});
var _cmd_privcheck_hijackablepath = ax.create_command("hijackablepath", "Checks the path environment variable for writable directories (FILE_ADD_FILE) that can be exploited to elevate privileges", "privcheck hijackablepath");
_cmd_privcheck_hijackablepath.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/hijackablepath." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks HijackablePath");
});
var _cmd_privcheck_tokenpriv = ax.create_command("tokenpriv", "Lists the current token privileges and highlights known vulnerable ones", "privcheck tokenpriv");
_cmd_privcheck_tokenpriv.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/tokenpriv." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks TokenPrivileges");
});
var _cmd_privcheck_unattendfiles = ax.create_command("unattendfiles", "Checks for leftover unattend files that might contain sensitive information", "privcheck unattendfiles");
_cmd_privcheck_unattendfiles.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unattendfiles." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks UnattendFiles");
});
var _cmd_privcheck_unquotedsvc = ax.create_command("unquotedsvc", "Checks for unquoted service paths", "privcheck unquotedsvc");
_cmd_privcheck_unquotedsvc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/unquotedsvc." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Unquoted Service Path");
});
var _cmd_privcheck_vulndrivers = ax.create_command("vulndrivers", "Checks if any service on the system uses a known vulnerable driver (based on loldrivers.io)", "privcheck vulndrivers");
_cmd_privcheck_vulndrivers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/vulndrivers." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Vulnerable Drivers");
});
var _cmd_privcheck_autologon = ax.create_command("autologon", "Checks for stored Autologon credentials in the Winlogon registry key", "privcheck autologon");
_cmd_privcheck_autologon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/autologon." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Autologon Credentials");
});
var _cmd_privcheck_credmanager = ax.create_command("credmanager", "Enumerates credentials stored in Windows Credential Manager", "privcheck credmanager");
_cmd_privcheck_credmanager.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/credmanager." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Credential Manager");
});
var _cmd_privcheck_modautorun = ax.create_command("modautorun", "Checks for modifiable autorun executables in Run/RunOnce registry keys", "privcheck modautorun");
_cmd_privcheck_modautorun.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/modautorun." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Modifiable Autoruns");
});
var _cmd_privcheck_modsvc = ax.create_command("modsvc", "Checks for services with modifiable permissions (DACL) that can be exploited for privilege escalation", "privcheck modsvc");
_cmd_privcheck_modsvc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/modsvc." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks Modifiable Services");
});
var _cmd_privcheck_pshistory = ax.create_command("pshistory", "Checks for PowerShell PSReadLine history file that may contain sensitive commands or credentials", "privcheck pshistory");
_cmd_privcheck_pshistory.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/pshistory." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks PowerShell History");
});
var _cmd_privcheck_uacstatus = ax.create_command("uacstatus", "Checks UAC status, integrity level, and local administrator group membership", "privcheck uacstatus");
_cmd_privcheck_uacstatus.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/uacstatus." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks UAC Status");
});
var _cmd_privcheck_all = ax.create_command("all", "Run all privilege escalation checks sequentially", "privcheck all");
_cmd_privcheck_all.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/privcheck_all." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "PrivCheck: all checks");
});
var cmd_privcheck = ax.create_command("privcheck", "Perform privilege escalation checks");
cmd_privcheck.addSubCommands([_cmd_privcheck_all, _cmd_privcheck_alwayselevated, _cmd_privcheck_autologon, _cmd_privcheck_credmanager, _cmd_privcheck_hijackablepath, _cmd_privcheck_modautorun, _cmd_privcheck_modsvc, _cmd_privcheck_tokenpriv, _cmd_privcheck_unattendfiles, _cmd_privcheck_unquotedsvc, _cmd_privcheck_pshistory, _cmd_privcheck_uacstatus, _cmd_privcheck_vulndrivers]);

var cmd_routeprint = ax.create_command("routeprint", "List IPv4 routes", "routeprint");
cmd_routeprint.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/routeprint." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: route");
});

var cmd_uptime = ax.create_command("uptime", "List system boot time and how long it has been running", "uptime");
cmd_uptime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/uptime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: uptime");
});

var cmd_useridletime = ax.create_command("useridletime", "Shows how long the user as been idle, displayed in seconds, minutes, hours and days", "useridletime");
cmd_useridletime.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/useridletime." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: useridletime");
});

var cmd_whoami = ax.create_command("whoami", "List whoami /all, hours and days", "whoami");
cmd_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/whoami." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: whoami /all");
});

var REGHIVES = {
    "HKLM":  2,
    "HKCU":  1,
    "HKU":   3,
    "HKCR":  0,
    "HKCC":  5,
};

var cmd_reg_query = ax.create_command(
    "reg_query",
    "Query a registry key or specific value.",
    "reg_query <HIVE> <path> [-h hostname] [-k value]\n" +
    "  reg_query HKLM -p SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\n" +
    "  reg_query HKLM -p SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion -k ProductName\n" +
    "  reg_query HKLM -p SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion -k ProductName -h 192.168.1.10"
);

cmd_reg_query.addArgString("hive", true);
cmd_reg_query.addArgFlagString("-h", "hostname", "Remote hostname or IP", "");
cmd_reg_query.addArgFlagString("-k", "key",      "Value name to query",   "");
cmd_reg_query.addArgFlagString("-p", "path",     "Registry path",         "");

cmd_reg_query.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {

    let rawHostname = parsed_json["hostname"] || "";
    let hostname    = rawHostname ? ("\\\\" + rawHostname) : "";
    let key         = parsed_json["key"]  || "";
    let path        = parsed_json["path"] || "";

    let hiveStr = (parsed_json["hive"] || "").toUpperCase();
    if (!(hiveStr in REGHIVES)) {
        ax.console_message(id, "Invalid hive: " + hiveStr + "\nExpected: HKLM, HKCU, HKU, HKCR, HKCC\n", "error");
        return;
    }
    let hive = REGHIVES[hiveStr];

    if (!path) {
        ax.console_message(id, "Missing registry path. Use -p <path>", "error");
        return;
    }

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [hostname, hive, path, key, 0]);
    let bof_path   = ax.script_dir() + "_bin/reg_query." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: reg_query");
});

var cmd_reg_query_recursive = ax.create_command(
    "reg_query_recursive",
    "Recursively enumerate all subkeys and values under a registry path.",
    "reg_query_recursive <HIVE> -p <path> [-h hostname]\n" +
    "  reg_query_recursive HKLM -p SOFTWARE\\\\Microsoft\n" +
    "  reg_query_recursive HKCU -p SOFTWARE -h 192.168.1.10"
);

cmd_reg_query_recursive.addArgString("hive", true);
cmd_reg_query_recursive.addArgFlagString("-h", "hostname", "Remote hostname or IP", "");
cmd_reg_query_recursive.addArgFlagString("-p", "path",     "Registry path",         "");

cmd_reg_query_recursive.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {

    let rawHostname = parsed_json["hostname"] || "";
    let hostname    = rawHostname ? ("\\\\" + rawHostname) : "";
    let path        = parsed_json["path"] || "";

    let hiveStr = (parsed_json["hive"] || "").toUpperCase();
    if (!(hiveStr in REGHIVES)) {
        ax.console_message(id, "Invalid hive: " + hiveStr + "\nExpected: HKLM, HKCU, HKU, HKCR, HKCC\n", "error");
        return;
    }
    if (!path) {
        ax.console_message(id, "Missing -p <path>", "error");
        return;
    }

    let hive = REGHIVES[hiveStr];

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [hostname, hive, path, "", 1]);
    let bof_path   = ax.script_dir() + "_bin/reg_query." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: reg_query_recursive");
});

var REG_TYPES = {
    "REG_SZ":         1,
    "REG_EXPAND_SZ":  2,
    "REG_BINARY":     3,
    "REG_DWORD":      4,
    "REG_QWORD":     11,
};

var cmd_reg_write = ax.create_command(
    "reg_write",
    "Write a registry value. Supported types: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY",
    "reg_write <HIVE> -p <path> -k <value_name> -t <type> -d <data> [-h hostname]\n" +
    "  reg_write HKLM -p SOFTWARE\\\\TestKey -k TestValue -t REG_SZ -d HelloWorld\n" +
    "  reg_write HKLM -p SOFTWARE\\\\TestKey -k DwordVal  -t REG_DWORD -d 1\n" +
    "  reg_write HKLM -p SOFTWARE\\\\TestKey -k TestValue -t REG_SZ -d HelloWorld -h 192.168.1.10"
);

cmd_reg_write.addArgString("hive", true);
cmd_reg_write.addArgFlagString("-h", "hostname", "Remote hostname or IP",  "");
cmd_reg_write.addArgFlagString("-p", "path",     "Registry key path",      "");
cmd_reg_write.addArgFlagString("-k", "key",      "Value name to write",    "");
cmd_reg_write.addArgFlagString("-t", "type",     "Registry type (REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_EXPAND_SZ)", "REG_SZ");
cmd_reg_write.addArgFlagString("-d", "data",     "Data to write",          "");

cmd_reg_write.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {

    let rawHostname = parsed_json["hostname"] || "";
    let hostname    = rawHostname ? ("\\\\" + rawHostname) : "";
    let path        = parsed_json["path"] || "";
    let key         = parsed_json["key"]  || "";
    let typeStr     = (parsed_json["type"] || "REG_SZ").toUpperCase();
    let dataStr     = parsed_json["data"] || "";

    let hiveStr = (parsed_json["hive"] || "").toUpperCase();
    if (!(hiveStr in REGHIVES)) {
        ax.console_message(id, "Invalid hive: " + hiveStr + "\nExpected: HKLM, HKCU, HKU, HKCR, HKCC\n", "error");
        return;
    }
    if (!path) {
        ax.console_message(id, "Missing -p <path>", "error");
        return;
    }
    if (!key) {
        ax.console_message(id, "Missing -k <value name>", "error");
        return;
    }
    if (!dataStr) {
        ax.console_message(id, "Missing -d <data>", "error");
        return;
    }
    if (!(typeStr in REG_TYPES)) {
        ax.console_message(id, "Invalid type: " + typeStr, "error");
        return;
    }

    let hive    = REGHIVES[hiveStr];
    let regtype = REG_TYPES[typeStr];

    // Data always packed as cstr — BOF owns type coercion for DWORD/QWORD
    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int,cstr", [hostname, hive, path, key, regtype, dataStr]);
    let bof_path   = ax.script_dir() + "_bin/reg_write." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: reg_write");
});

var cmd_reg_delete = ax.create_command(
    "reg_delete",
    "Delete a registry value (-k) or an entire key (omit -k). Key must have no subkeys to be deleted.",
    "reg_delete <HIVE> -p <path> [-k value] [-h hostname]\n" +
    "  reg_delete HKLM -p SOFTWARE\\\\TestKey -k TestValue\n" +
    "  reg_delete HKLM -p SOFTWARE\\\\TestKey\n" +
    "  reg_delete HKLM -p SOFTWARE\\\\TestKey -k TestValue -h 192.168.1.10"
);

cmd_reg_delete.addArgString("hive", true);
cmd_reg_delete.addArgFlagString("-h", "hostname", "Remote hostname or IP", "");
cmd_reg_delete.addArgFlagString("-p", "path",     "Registry key path",    "");
cmd_reg_delete.addArgFlagString("-k", "key",      "Value name to delete (omit to delete the key itself)", "");

cmd_reg_delete.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {

    let rawHostname = parsed_json["hostname"] || "";
    let hostname    = rawHostname ? ("\\\\" + rawHostname) : "";
    let path        = parsed_json["path"] || "";
    let key         = parsed_json["key"]  || "";

    let hiveStr = (parsed_json["hive"] || "").toUpperCase();
    if (!(hiveStr in REGHIVES)) {
        ax.console_message(id, "Invalid hive: " + hiveStr + "\nExpected: HKLM, HKCU, HKU, HKCR, HKCC\n", "error");
        return;
    }
    if (!path) {
        ax.console_message(id, "Missing -p <path>", "error");
        return;
    }

    let hive = REGHIVES[hiveStr];

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr", [hostname, hive, path, key]);
    let bof_path   = ax.script_dir() + "_bin/reg_delete." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: reg_delete");
});

var cmd_reg_find = ax.create_command(
    "reg_find",
    "Search registry values by name or data under a path (recursive). Use -m to control match mode.",
    "reg_find <HIVE> -p <path> -s <pattern> [-m name|data|both] [-h hostname]\n" +
    "  reg_find HKLM -p SOFTWARE -s password\n" +
    "  reg_find HKLM -p SOFTWARE -s password -m both\n" +
    "  reg_find HKLM -p SYSTEM\\\\CurrentControlSet -s autologon -m name -h 192.168.1.10"
);

cmd_reg_find.addArgString("hive", true);
cmd_reg_find.addArgFlagString("-h", "hostname", "Remote hostname or IP",                    "");
cmd_reg_find.addArgFlagString("-p", "path",     "Registry root path to search under",       "");
cmd_reg_find.addArgFlagString("-s", "pattern",  "Search pattern (case-insensitive)",        "");
cmd_reg_find.addArgFlagString("-m", "mode",     "Match mode: name, data, both (default: name)", "name");

cmd_reg_find.setPreHook(function(id, cmdline, parsed_json, ...parsed_lines) {

    let rawHostname = parsed_json["hostname"] || "";
    let hostname    = rawHostname ? ("\\\\" + rawHostname) : "";
    let path        = parsed_json["path"]    || "";
    let pattern     = parsed_json["pattern"] || "";
    let modeStr     = (parsed_json["mode"]   || "name").toLowerCase();

    let hiveStr = (parsed_json["hive"] || "").toUpperCase();
    if (!(hiveStr in REGHIVES)) {
        ax.console_message(id, "Invalid hive: " + hiveStr + "\nExpected: HKLM, HKCU, HKU, HKCR, HKCC\n", "error");
        return;
    }
    if (!path) {
        ax.console_message(id, "Missing -p <path>", "error");
        return;
    }
    if (!pattern) {
        ax.console_message(id, "Missing -s <pattern>", "error");
        return;
    }

    let modeMap = { "name": 0, "data": 1, "both": 2 };
    if (!(modeStr in modeMap)) {
        ax.console_message(id, "Invalid -m mode. Use: name, data, both", "error");
        return;
    }

    let hive        = REGHIVES[hiveStr];
    let search_type = modeMap[modeStr];

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [hostname, hive, path, pattern, search_type]);
    let bof_path   = ax.script_dir() + "_bin/reg_find." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: reg_find");
});

var group_test = ax.create_commands_group("SAL-BOF", [cmd_arp, cmd_cacls, cmd_dir, cmd_env, cmd_ipconfig, cmd_listdns, cmd_netstat, cmd_nslookup, cmd_privcheck, cmd_routeprint, cmd_uptime, cmd_useridletime, cmd_whoami, cmd_reg_query, cmd_reg_query_recursive, cmd_reg_write, cmd_reg_delete, cmd_reg_find]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);
