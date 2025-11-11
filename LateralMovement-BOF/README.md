# LateralMovement-BOF

BOFs kit for lateral movements

![](_img/01.png)

## jump psexec

Attempt to spawn a session on a remote target via PsExec

```
jump psexec [-b binary_name] [-s share] [-p svc_path] [-n svc_name] [-d svc_description] <target> <binary>
```

## jump scshell

Attempt to spawn a session on a remote target via SCShell

```
jump scshell [-b binary_name] [-s share] [-p svc_path] [-n svc_name] <target> <binary>
```

## invoke winrm

Use WinRM to execute commands on other systems

```
invoke winrm <computer> <command>
```

## invoke scshell

Use SCShell to execute commands on other systems by modifying service binary path (fileless)

```
invoke scshell [-i] <target> <service> <payload>
```

## token make

Creates an impersonated token from a given credentials

```
token make <username> <password> <domain> <type>
```

![](_img/02.png)

The **Make token** item will be added to the **Access** menu in the Sessions Table and Graph.

![](_img/03.png)

![](_img/04.png)



## token steal

Steal access token from a process

```
token steal <pid>
```

The **Steal token** item will be added to the context menu in the Process Browser.

![](_img/05.png)
