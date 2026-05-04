var metadata = {
    name: "SAL-BOF",
    description: "Situation Awareness Local BOFs"
};

// ax.script_import(ax.script_dir() + "clipboard/clipboard.axs")
// ax.script_import(ax.script_dir() + "sc_bof/svcmgr.axs")

// *********************** clipboard ***********************

var cmd_clipboard = ax.create_command(
    "clipboard",
    "Read the current system clipboard contents [NOISE: low]",
    "clipboard"
);

cmd_clipboard.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    var bof_path = ax.script_dir() + "_bin/clipboard." + ax.arch(id) + ".o";

    if (!ax.file_exists(bof_path)) {
        ax.console_message(id,
            "BOF not found: " + bof_path,
            "error",
            "Compile clipboard.c and place the .o files under _bin/ next to this script."
        );
        return;
    }

    var hook = function (task) {
        if (!task.text) return task;

        var lines = task.text.split("\n");
        var out   = [];

        for (var i = 0; i < lines.length; i++) {
            var l = lines[i];
            if (/^\[Clipboard\s*\//.test(l)) {
                var fmt = /Unicode/.test(l) ? "Unicode" : "ANSI";
                out.push("[Clipboard capture — " + fmt + "]");
                continue;
            }
            out.push(l);
        }

        task.text = out.join("\n");
        return task;
    };

    ax.execute_alias_hook(
        id,
        cmdline,
        "execute bof " + bof_path,
        "Task: Clipboard capture (BOF)",
        hook
    );
});


// *********************** clipboard end ***********************
// ***********************     sc_bof    ***********************

var cmd_svc_list = ax.create_command(
    "svc_list",
    "List all services (local or remote).",
    "svc_list | svc_list -c 192.168.1.10 | svc_list -f driver");
cmd_svc_list.addArgFlagString("-c", "computer", "Remote computer (skip = localhost)", "localhost");
cmd_svc_list.addArgFlagString("-f", "filter",   "Filter: all | win32 | driver", "all");
cmd_svc_list.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var computer   = parsed_json["computer"] || "localhost";
    var filter     = parsed_json["filter"]   || "all";
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["list", computer, filter]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_list on " + computer, null);
});

var cmd_svc_query = ax.create_command(
    "svc_query",
    "Check the status and configuration of a service.",
    "svc_query -n WinDefend | svc_query -n Spooler -c 192.168.1.10");
cmd_svc_query.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_query.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }

    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["query", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof "${bof_path}" "${bof_params}"`,
        "Task: svc_query [" + svcname + "] on " + computer, null);
});

var cmd_svc_create = ax.create_command(
    "svc_create",
    "Create a new service (Win32 or kernel driver).",
    "svc_create -n MySvc -p C:\\\\path\\\\svc.exe -t win32 -s auto | svc_create -n MyDrv -p C:\\\\path\\\\drv.sys -t driver -s demand");
cmd_svc_create.addArgFlagString("-n", "svcname",   "Service internal name");
cmd_svc_create.addArgFlagString("-p", "binpath",   "Path to the executable or .sys file");
cmd_svc_create.addArgFlagString("-d", "dispname",  "Display name (optional)", "");
cmd_svc_create.addArgFlagString("-t", "svctype",   "Type: win32 | driver", "win32");
cmd_svc_create.addArgFlagString("-s", "starttype", "Start: auto | demand | disabled | boot | system", "demand");
cmd_svc_create.addArgFlagString("-c", "computer",  "Remote machine (skip = localhost)", "localhost");
cmd_svc_create.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]   || "";
    var binpath    = parsed_json["binpath"]   || "";
    var dispname   = parsed_json["dispname"]  || "";
    var svctype    = parsed_json["svctype"]   || "win32";
    var starttype  = parsed_json["starttype"] || "demand";
    var computer   = parsed_json["computer"]  || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    if (!binpath) { ax.console_message(id, "missing -p <binpath>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr",
        ["create", computer, svcname, dispname, binpath, svctype, starttype]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_create [" + svcname + "] on " + computer, null);
});

var cmd_svc_delete = ax.create_command(
    "svc_delete",
    "Remove a service (stops it first if running).",
    "svc_delete -n MySvc | svc_delete -n MySvc -c 192.168.1.10");
cmd_svc_delete.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_delete.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["delete", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_delete [" + svcname + "] on " + computer, null);
});

var cmd_svc_start = ax.create_command(
    "svc_start",
    "Start a service and wait for RUNNING confirmation.",
    "svc_start -n Spooler | svc_start -n MySvc -c 192.168.1.10");
cmd_svc_start.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_start.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_start.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["start", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_start [" + svcname + "] on " + computer, null);
});

var cmd_svc_stop = ax.create_command(
    "svc_stop",
    "Stop a service and wait for STOPPED confirmation.",
    "svc_stop -n Spooler | svc_stop -n MySvc -c 192.168.1.10");
cmd_svc_stop.addArgFlagString("-n", "svcname",  "Service name");
cmd_svc_stop.addArgFlagString("-c", "computer", "Remote machine (skip = localhost)", "localhost");
cmd_svc_stop.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var svcname    = parsed_json["svcname"]  || "";
    var computer   = parsed_json["computer"] || "localhost";
    if (!svcname) { ax.console_message(id, "missing -n <svcname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/svcmgr." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("cstr,cstr,cstr", ["stop", computer, svcname]);
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: svc_stop [" + svcname + "] on " + computer, null);
});
// ***********************  sc_bof end   ***********************

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

var group_test = ax.create_commands_group("SAL-BOF", [cmd_arp, cmd_cacls, cmd_dir, cmd_env, cmd_ipconfig, cmd_listdns, cmd_netstat, cmd_nslookup, cmd_privcheck, cmd_routeprint, cmd_uptime, cmd_useridletime, cmd_whoami, cmd_clipboard, cmd_svc_list, cmd_svc_query, cmd_svc_create, cmd_svc_delete, cmd_svc_start, cmd_svc_stop]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);
