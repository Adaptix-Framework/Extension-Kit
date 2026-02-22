var metadata = {
    name: "",
    description: "",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "AD-BOF/ad.axs");
ax.script_load(path + "AD-BOF/ad-services.axs");
ax.script_load(path + "Creds-BOF/creds.axs");
ax.script_load(path + "Elevation-BOF/elevate.axs");
ax.script_load(path + "Execution-BOF/execution.axs");
ax.script_load(path + "Injection-BOF/inject.axs");
ax.script_load(path + "LateralMovement-BOF/lateral.axs");
ax.script_load(path + "Postex-BOF/postex.axs");
ax.script_load(path + "Process-BOF/process.axs");
ax.script_load(path + "SAL-BOF/sal.axs");
ax.script_load(path + "SAR-BOF/sar.axs");
