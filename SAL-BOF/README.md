# SAL-BOF

This extension enhances situational awareness by providing a set of local Beacon Object File (BOF) commands. These commands allow the operator to gather detailed information about the target system's network configuration, file access control, environment variables, and other critical system details.

![](_img/01.png)

## arp

List ARP table

```
arp
```

## cacls

List user permissions for the specified file or directory, wildcards supported

```
cacls <path>
```

## env

List process environment variables

```
env
```

## ipconfig

List IPv4 address, hostname, and DNS server

```
ipconfig
```

## listdns

List DNS cache entries. Attempt to query and resolve each

```
listdns
```

## nslookup

Make a DNS query

```
nslookup <domain> [server] [type>]
```

# privcheck

BOFs to detect common privilege escalation paths in Windows. This is taken from [ostrichgolf/PrivCheck](https://github.com/ostrichgolf/PrivCheck) which was originally forked from [mertdas/PrivKit](https://github.com/mertdas/PrivKit). PrivCheck currently includes the following modules:

```
privcheck <module>
```

| Module           | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| `alwayselevated` | Checks if `Always Install Elevated` is enabled using the registry. |
| `hijackablepath` | Checks the path environment variable for writable directories (`FILE_ADD_FILE`) that can be exploited to elevate privileges. |
| `tokenpriv`      | Lists the current token privileges and highlights known vulnerable ones. |
| `unattendfiles`  | Checks for leftover unattend files that might contain sensitive information. |
| `unquotedsvc`    | Checks for unquoted service paths.                           |
| `vulndrivers`    | Checks if any service on the system uses a known vulnerable driver (based on loldrivers.io).  *The list of vulnerable drivers is downloaded from `loldrivers.io` during compilation, then baked into the BOF. Recompile periodically to update* . |



## routeprint

List IPv4 routes

```
routeprint
``` 

## uptime

List system uptime

```
uptime
```

## useridletime

Shows how long the user as been idle, displayed in seconds, minutes, hours and days.

```
useridletime
```

## whoami

List whoami /all

```
whoami
```



## Credits
* CS-Situational-Awareness-BOF - https://github.com/trustedsec/CS-Situational-Awareness-BOF
* PrivCheck - https://github.com/ostrichgolf/PrivCheck
* C2-Tool-Collection - https://github.com/outflanknl/C2-Tool-Collection/