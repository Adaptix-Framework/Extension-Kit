var metadata = {
    name: "SAR-BOF",
    description: "Situation Awareness Remote BOFs"
};

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

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Scan Target: " + target);
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

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var cmd_quser = ax.create_command("quser", "Query user sessions on a remote machine, providing session information", "quser MainDC");
cmd_quser.addArgString("host", "", "localhost");
cmd_quser.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let host = parsed_json["host"];

    let bof_params = ax.bof_pack("cstr", [host]);
    let bof_path = ax.script_dir() + "_bin/quser." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: quser");
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
        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
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

        ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message, targets_handler);
    }
});

var group_test = ax.create_commands_group("SAR-BOF", [cmd_smartscan, cmd_taskhound, cmd_quser, cmd_nbtscan]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);