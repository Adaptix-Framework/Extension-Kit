var metadata = {
    name: "BofHound-Parser-V1",
    description: "Create proper logs for Bofhound using ldapsearch, parses and stitches the entire output to avoid any kind of break during long queries",
};

var logDir = "~/AdaptixC2/Logs/"; 

var outputBuffer = {};

// --- INTERNAL REPAIR ENGINE ---
// We define this separately so we can call it on the final dangling buffer too.
var repair_ldap_segment = function(segment) {
    if (segment.trim().length < 20) return "";

    // 1. Initial Cleaning (Remove nulls, normalize newlines)
    var clean = segment.replace(/\0/g, '').replace(/\r\n/g, "\n").replace(/\r/g, "\n");

    // 2. FIX COLLISION: Smashed Attributes
    var attributesToFix = [
        "name", "objectGUID", "userAccountControl", "badPwdCount", 
        "codePage", "countryCode", "badPasswordTime", "lastLogoff", 
        "lastLogon", "pwdLastSet", "primaryGroupID", "objectSid", 
        "adminCount", "accountExpires", "logonCount", "sAMAccountName", 
        "sAMAccountType", "userPrincipalName", "objectCategory", 
        "isCriticalSystemObject", "distinguishedName", "instanceType", 
        "whenCreated", "whenChanged", "uSNCreated", "uSNChanged", 
        "member", "memberOf", "groupType", "dSCorePropagationData",
        "displayName", "title", "description", "department"
    ];

    for (var j = 0; j < attributesToFix.length; j++) {
        var attr = attributesToFix[j];
        var re = new RegExp("([a-zA-Z0-9])" + attr + ":", "g");
        clean = clean.replace(re, "$1\n" + attr + ":");
    }

    // 3. THE STITCHER: Join multi-line nTSecurityDescriptor
    var b64Regex = /(nTSecurityDescriptor:[\s\S]*?)(?=\n[a-zA-Z\-]+:|\n-{10,}|$)/g;
    clean = clean.replace(b64Regex, function(match) {
        var lines = match.split("\n");
        var header = lines[0].split(":")[0] + ": ";
        var blob = lines.join("").split(":")[1].replace(/\s+/g, "");
        return header + blob;
    });

    // 4. FIX PADDING
    clean = clean.replace(/nTSecurityDescriptor: ([A-Za-z0-9+/=]+)/g, function(match, b64) {
        var paddedB64 = b64.trim();
        while (paddedB64.length % 4 !== 0) { paddedB64 += "="; }
        return "nTSecurityDescriptor: " + paddedB64;
    });

    // 5. REMOVE EMPTY LINES
    var lines = clean.split("\n");
    var finalLines = [];
    for (var k = 0; k < lines.length; k++) {
        if (lines[k].trim().length > 0) {
            finalLines.push(lines[k].trim());
        }
    }
    
    return finalLines.join("\n") + "\n--------------------\n\n";
};

var bofhound_handler = function(input) {
    var rawChunk = "";
    var taskId = "default";

    if (typeof input === 'object') {
        rawChunk = input.text || "";
        taskId = input.task_id || "default";
    } else {
        rawChunk = String(input);
    }

    if (!rawChunk) return;

    if (!outputBuffer[taskId]) {
        outputBuffer[taskId] = "";
    }
    outputBuffer[taskId] += rawChunk;

    // --- MAIN STREAM PROCESSING ---
    if (outputBuffer[taskId].indexOf("--------------------") !== -1) {
        try {
            var parts = outputBuffer[taskId].split("--------------------");
            outputBuffer[taskId] = parts.pop(); 

            var processedData = "";
            for (var i = 0; i < parts.length; i++) {
                processedData += repair_ldap_segment(parts[i]);
            }

            if (processedData.length > 0) {
                var uniquePath = logDir + "LDAP_data_" + taskId + "_" + new Date().getTime() + ".log";
                ax.file_write_text(uniquePath, processedData);
                ax.log("[+] BofHound: Saved " + parts.length + " objects to " + uniquePath);
            }
        } catch (e) {
            ax.log("[-] Harvester Error: " + e.toString());
        }
    }

    // --- FINAL COMPLETION FLUSH ---
    // This now uses the SAME repair logic as the main stream
    if (rawChunk.indexOf("retrieved") !== -1 && rawChunk.indexOf("results total") !== -1) {
        if (outputBuffer[taskId] && outputBuffer[taskId].trim().length > 10) {
            
            // We run the final fragment through the repair engine
            var finalCleanedObj = repair_ldap_segment(outputBuffer[taskId]);
            
            if (finalCleanedObj.length > 10) {
                var finalPath = logDir + "LDAP_final_" + taskId + "_" + new Date().getTime() + ".log";
                ax.file_write_text(finalPath, finalCleanedObj);
                ax.log("[!] BofHound: Final record repaired and flushed to " + finalPath);
            }
        }
        delete outputBuffer[taskId];
    }

    if (typeof input === 'object' && input.agent) {
        ax.console_message(input.agent, rawChunk);
    }
};

// ... (Rest of the script: cmd_ldap_bh and Registration remain the same)

var cmd_ldap_bh = ax.create_command("ldapsearch_bh", "Unified BofHound Search", "ldapsearch_bh (objectClass=*) -a *,ntsecuritydescriptor");

cmd_ldap_bh.addArgString("query", true);
cmd_ldap_bh.addArgFlagString("-a", "attributes", "The attributes to retrieve", "*");
cmd_ldap_bh.addArgFlagInt("-c", "count", "The result max size", 0);
cmd_ldap_bh.addArgFlagInt("-s", "scope", "1=BASE, 2=LEVEL, 3=SUBTREE", 3);
cmd_ldap_bh.addArgFlagString("--dc", "dc", "DC Hostname/IP", "");
cmd_ldap_bh.addArgFlagString("--dn", "dn", "LDAP query base", "");
cmd_ldap_bh.addArgBool("--ldaps", "Use LDAPS");

cmd_ldap_bh.setPreHook(function(id, cmdline, parsed_json) {
    let query      = parsed_json["query"];
    let attributes = parsed_json["attributes"];
    let count      = parsed_json["count"];
    let scope      = parsed_json["scope"];
    let dc         = parsed_json["dc"];
    let dn         = parsed_json["dn"];
    let ldaps      = parsed_json["--ldaps"] ? 1 : 0;

    let bof_params = ax.bof_pack("wstr,cstr,int,int,cstr,cstr,int", [query, attributes, count, scope, dc, dn, ldaps]);
    let bof_path = ax.script_dir() + "AD-BOF/_bin/ldapsearch." + ax.arch(id) + ".o";

    ax.execute_command_handler(id, "execute bof \"" + bof_path + "\" " + bof_params, bofhound_handler);
    ax.log("[*] Tasked LDAP query. Unified repair engine active.");
});

try {
    var group = ax.create_commands_group("BofHound", [cmd_ldap_bh]);
    ax.register_commands_group(group, ["beacon"], ["windows"], []);
} catch (e) {
    ax.log("[-] Registration failed: " + e);
}
