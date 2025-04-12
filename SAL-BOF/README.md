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

## dir

Lists files in a specified directory. Supports wildcards (e.g. "C:\Windows\S*"). Optionally, it can perform a recursive list with the `/s` argument

```
dir [path] [/s]
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