var metadata = {
    name: "",
    description: "",
    nosave: true
};

var path = ax.script_dir();
ax.script_load(path + "ADCS-BOF/ADCS.axs")
ax.script_load(path + "Kerbeus-BOF/kerbeus.axs")
ax.script_load(path + "SQL-BOF/SQL.axs")
ax.script_load(path + "LDAP-BOF/LDAP.axs")
ax.script_load(path + "RelayInformer/RelayInformer.axs")