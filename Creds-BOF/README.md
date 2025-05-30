# Creds-BOF

BOF tools that can be used to harvest passwords.

![](_img/01.png)

## autologon

Checks the registry for autologon information.

```
autologon
```



## askcreds

A BOF tool that can be used to collect passwords using CredUIPromptForWindowsCredentialsName.

```
askcreds [-p prompt] [-n note] [-t wait_time]
```



## credman

Checks the current user's Windows Credential Manager for saved web passwords and returns them.

```
credman
```

## hashdump

Gathers NTLM hashes from SAM and SYSTEM.

```
hashdump
```

## Credits
* C2-Tool-Collection - https://github.com/outflanknl/C2-Tool-Collection
* PrivCheck - https://github.com/ostrichgolf/PrivCheck