var metadata = {
    name: "",
    description: "",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "callbacks/callbacks.axs")
ax.script_load(path + "ETW/etw_ti.axs")
ax.script_load(path + "ppl/ppl.axs")
