# SQL-BOF
A library of beacon object files to interact with remote SQL servers and data. This collection is templated off the TrustedSec [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) collection and models the functionality of the [SQLRecon](https://github.com/skahwah/SQLRecon) project.

## Available commands
|Commands| Usage                                                                                   |Notes|
|--------|-----------------------------------------------------------------------------------------|-----|
|mssql 1434udp| [server IP]                                                                             |Enumerate SQL Server connection info |
|mssql adsi| [server] [ADSI_linkedserver] [-p port] [-d database] [-l linkedserver] [-i impersonate] |Obtain ADSI creds from ADSI linked server |
|mssql agentcmd | [server] [command] [-d database] [-l linkedserver] [-i impersonate]                     |Execute a system command using agent jobs |
|mssql agentstatus | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate SQL agent status and jobs |
|mssql checkrpc | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate RPC status of linked servers |
|mssql clr | [server] [dll_path] [function] [-d database] [-l linkedserver] [-i impersonate]         |Load and execute .NET assembly in a stored procedure |
|mssql columns | [server] [table] [-d database] [-l linkedserver] [-i impersonate]                       |Enumerate columns within a table |
|mssql databases | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate databases on a server|
|mssql disableclr | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Disable CLR integration |
|mssql disableole | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Disable OLE Automation Procedures |
|mssql disablerpc | [server] [linkedserver] [-d database] [-i impersonate]                                  |Disable RPC and RPC out on a linked server |
|mssql disablexp | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Disable xp_cmdshell |
|mssql enableclr | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enable CLR integration |
|mssql enableole | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enable OLE Automation Procedures |
|mssql enablerpc | [server] [linkedserver] [-d database] [-i impersonate]                                  |Enable RPC and RPC out on a linked server |
|mssql enablexp | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enable xp_cmdshell |
|mssql impersonate | [server] [-d database]                                                                  |Enumerate users that can be impersonated |
|mssql info | [server] [-d database]                                                                  |Gather information about the SQL server |
|mssql links | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate linked servers |
|mssql olecmd | [server] [command] [-d database] [-l linkedserver] [-i impersonate]                     |Execute a system command using OLE automation procedures |
|mssql query | [server] [query] [-d database] [-l linkedserver] [-i impersonate]                       |Execute a custom SQL query |
|mssql rows | [server] [table] [-d database] [-l linkedserver] [-i impersonate]                       |Get the count of rows in a table |
|mssql search | [server] [search] [-d database] [-l linkedserver] [-i impersonate]                      |Search a table for a column name |
|mssql smb | [server] [\\\\listener] [-d database] [-l linkedserver] [-i impersonate]                |Coerce NetNTLM auth via xp_dirtree |
|mssql tables | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate tables within a database |
|mssql users | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Enumerate users with database access |
|mssql whoami | [server] [-d database] [-l linkedserver] [-i impersonate]                               |Gather logged in user, mapped user and roles |
|mssql xpcmd | [server] [command] [-d database] [-l linkedserver] [-i impersonate]                     |Execute a system command via xp_cmdshell |

## References
- [SQLRecon](https://github.com/skahwah/SQLRecon) by [@sanjivkawa](https://twitter.com/sanjivkawa)
- [PySQLRecon](https://github.com/Tw1sm/PySQLRecon)
- [CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF)
