var metadata = {
    name: "SAR-BOF",
    description: "Situation Awareness Remote BOFs"
};

ax.script_import(ax.script_dir() + "EdrEnum-BOF/edr.axs")

// ************************ ghost_task ************************

var cmd_ghost_add = ax.create_command(
    "ghost_task_add",
    "Create a ghost scheduled task via registry (requires SYSTEM).",
    "ghost_task_add -n TaskName -p C:\\\\Windows\\\\System32\\\\cmd.exe -a \"/c whoami\" -s second -t 30 | ghost_task_add -n TaskName -p C:\\\\payload.exe -s daily -t 22:30 -u SYSTEM | ghost_task_add -n TaskName -p C:\\\\payload.exe -s weekly -t 09:00 -d monday,friday");
cmd_ghost_add.addArgFlagString("-n", "taskname", "Scheduled task name");
cmd_ghost_add.addArgFlagString("-p", "program",  "Executable path");
cmd_ghost_add.addArgFlagString("-s", "stype",    "Trigger: second | daily | weekly | logon");
cmd_ghost_add.addArgFlagString("-t", "time",     "HH:MM (daily/weekly) or N seconds (second)", "0");
cmd_ghost_add.addArgFlagString("-u", "username", "User to run the task as", "SYSTEM");
cmd_ghost_add.addArgFlagString("-a", "argument", "Arguments for the executable", "");
cmd_ghost_add.addArgFlagString("-d", "days",     "Days for weekly trigger (ex: monday,friday)", "monday");
cmd_ghost_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var taskname   = parsed_json["taskname"] || "";
    var program    = parsed_json["program"]  || "";
    var stype      = parsed_json["stype"]    || "";
    var time_val   = parsed_json["time"]     || "0";
    var username   = parsed_json["username"] || "SYSTEM";
    var argument   = parsed_json["argument"] || "";
    var days       = parsed_json["days"]     || "monday";
    if (!taskname) { ax.console_message(id, "missing -n <taskname>", "error"); return; }
    if (!program)  { ax.console_message(id, "missing -p <program>",  "error"); return; }
    if (!stype)    { ax.console_message(id, "missing -s <stype>: second | daily | weekly | logon", "error"); return; }
    var stype_lower = stype.toLowerCase();
    var pack_types, pack_args;
    if (stype_lower === "weekly") {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [9, "add", taskname, program, argument, username, stype, time_val, days];
    } else if (stype_lower === "logon") {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [7, "add", taskname, program, argument, username, stype];
    } else {
        pack_types = "int,cstr,cstr,cstr,cstr,cstr,cstr,cstr";
        pack_args  = [8, "add", taskname, program, argument, username, stype, time_val];
    }
    var bof_path   = ax.script_dir() + "_bin/GhostTask." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack(pack_types, pack_args);
    if (!ax.file_exists(bof_path)) { ax.console_message(id, "BOF not found: " + bof_path, "error"); return; }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: GhostTask add [" + taskname + "]", null);
});

var cmd_ghost_delete = ax.create_command(
    "ghost_task_delete",
    "Delete a ghost scheduled task from the registry (requires SYSTEM). [NOISE: low]",
    "ghost_task_delete -n TaskName");
cmd_ghost_delete.addArgFlagString("-n", "taskname", "Name of the task to delete");
cmd_ghost_delete.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var taskname   = parsed_json["taskname"] || "";
    if (!taskname) { ax.console_message(id, "missing -n <taskname>", "error"); return; }
    var bof_path   = ax.script_dir() + "_bin/GhostTask." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int,cstr,cstr", [3, "delete", taskname]);
    if (!ax.file_exists(bof_path)) { ax.console_message(id, "BOF not found: " + bof_path, "error"); return; }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: GhostTask delete [" + taskname + "]", null);
});


// ************************ ghost_task end ************************


var cmd_smartscan = ax.create_command("smartscan", "Smart port scan", "smartscan 192.168.1.1 -p 80,443,22-25");
cmd_smartscan.addArgString("target", true, "Destination IP address, range or CIDR format (for example: '192.168.1.1' , '192.168.1.1-192.168.1.10' , '192.168.1.1,192.168.1.3' or '192.168.1.1/24')");
cmd_smartscan.addArgFlagString("-p", "ports", "Port range: 'fast', 'standart', 'full', or custom ports (e.g. 80,443,22-25,3389)", "standart");
cmd_smartscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let ports = parsed_json["ports"];

    let scan_level = 0;
    let custom_ports = "";

    if (ports === "fast") {
        scan_level = 1;
    }
    else if (ports === "standart") {
        scan_level = 2;
    }
    else if (ports === "full") {
        scan_level = 3;
    }
    else if (ports) {
        custom_ports = ports;
    }

    let bof_params = ax.bof_pack("cstr,int,cstr", [target, scan_level, custom_ports]);
    let bof_path = ax.script_dir() + "_bin/smartscan." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof -a "${bof_path}" ${bof_params}`, "Scan Target: " + target);
});



var cmd_taskhound = ax.create_command("taskhound",
    "Collect scheduled tasks from remote systems",
    "taskhound 192.168.1.100 -u domain\\admin -p password -save C:\\Output -unsaved-creds -grab-blobs");
cmd_taskhound.addArgString("target", true, "Remote system to collect from (IP or hostname)");
cmd_taskhound.addArgFlagString("-u", "username", "Username for authentication", "");
cmd_taskhound.addArgFlagString("-p", "password", "Password for authentication", "");
cmd_taskhound.addArgFlagString("-save", "save_directory", "Directory to save XML files", "");
cmd_taskhound.addArgBool("-unsaved-creds", "Show tasks without stored credentials");
cmd_taskhound.addArgBool("-grab-blobs", "Also collect credential blobs and masterkeys (requires -save)");

cmd_taskhound.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let username = parsed_json["username"] || "";
    let password = parsed_json["password"] || "";
    let save_dir = parsed_json["save_directory"] || "";
    let flags = "";

    if(parsed_json["-unsaved-creds"]) { flags += "-unsaved-creds "; }
    if(parsed_json["-grab-blobs"]) { flags += "-grab-blobs"; }
    flags = flags.trim();

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [target, username, password, save_dir, flags]);

    let bof_path = ax.script_dir() + "_bin/taskhound." + ax.arch(id) + ".o";
    let message = `Taskhound from ${target}`;

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});



var cmd_quser = ax.create_command("quser", "Query user sessions on a remote machine, providing session information", "quser MainDC");
cmd_quser.addArgString("host", "", "localhost");
cmd_quser.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr", [host]);
    let bof_path = ax.script_dir() + "_bin/quser." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "BOF implementation: quser");
});



var cmd_nbtscan = ax.create_command("nbtscan", "NetBIOS name scanner (nbtscan-like)", "nbtscan 192.168.1.0/24 -v");
cmd_nbtscan.addArgString("target", true, "Destination IP address, range or CIDR (e.g. '192.168.1.1', '192.168.1.1-192.168.1.20', '192.168.1.0/24', '192.168.1.1,192.168.1.5')");
cmd_nbtscan.addArgBool("-v", "verbose");
cmd_nbtscan.addArgBool("-q", "quiet");
cmd_nbtscan.addArgBool("-e", "etc_hosts");
cmd_nbtscan.addArgBool("-l", "lmhosts");
cmd_nbtscan.addArgFlagString("-s", "separator", "Script-friendly output separator (enables script mode)", "");
cmd_nbtscan.addArgFlagString("-t", "timeout", "Response timeout in milliseconds (default 1000)", "");
cmd_nbtscan.addArgBool("-no-targets", "Disable automatic target registration");
cmd_nbtscan.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target    = parsed_json["target"];
    let verbose   = parsed_json["-v"] ? 1 : 0;
    let quiet     = parsed_json["-q"] ? 1 : 0;
    let etc_hosts = parsed_json["-e"] ? 1 : 0;
    let lmhosts   = parsed_json["-l"] ? 1 : 0;
    let sep       = parsed_json["separator"] || "";
    let timeout_s = parsed_json["timeout"] || "";
    let no_targets = parsed_json["-no-targets"] ? 1 : 0;

    let timeout_ms = 1000;
    if (timeout_s) {
        let parsed = parseInt(timeout_s, 10);
        if (!isNaN(parsed) && parsed > 0 && parsed < 600000) {
            timeout_ms = parsed;
        }
    }

    let bof_params = ax.bof_pack("cstr,int,int,int,int,cstr,int", [ target, verbose, quiet, etc_hosts, lmhosts, sep, timeout_ms ]);
    let bof_path = ax.script_dir() + "_bin/nbtscan." + ax.arch(id) + ".o";
    let message = "NBTscan: " + target;

    if(no_targets == 1) {
        ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
    }
    else {
        let targets_handler = function (task) {
            let blocks = task.text.trim().split('\n');
            var results = [];
            const ipRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^\s]+)\s+([^\s]+)/;
            for (const line of blocks) {

                if (results.length > 1000) {
                    ax.targets_add_list(results);
                    results.length = 0;
                }

                const match = line.trim().match(ipRegex);
                if (!match)
                    continue;

                const [, ip, netbiosName, domain] = match;

                const octets = ip.split('.');
                const isValid = octets.length === 4 &&
                    octets.every(octet => {
                        const num = parseInt(octet, 10);
                        return num >= 0 && num <= 255 && /^\d+$/.test(octet);
                    });
                if (!isValid)
                    continue;

                const obj = {
                    address: ip,
                    computer: netbiosName,
                    domain: domain,
                    alive: true,
                    info: "collected from nbtscan"
                };
                results.push(obj);
            }
            if (results.length > 0) ax.targets_add_list(results);
            return task;
        }

        ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message, targets_handler);
    }
});

var group_test = ax.create_commands_group("SAR-BOF", [cmd_enum_edr, cmd_smartscan, cmd_taskhound, cmd_quser, cmd_nbtscan, cmd_ghost_add, cmd_ghost_delete]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);
