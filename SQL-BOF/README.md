# SQL-BOF

A library of beacon object files to interact with remote SQL servers and data. This collection is a port of [@Tw1sm](https://github.com/Tw1sm)'s [SQL-BOF](https://github.com/Tw1sm/SQL-BOF).

![0](./_img/01.png)

## Available commands

| Commands        | Usage                                                        | Notes                                                    |
| --------------- | ------------------------------------------------------------ | -------------------------------------------------------- |
| sql-1434udp     | [server IP]                                                  | Enumerate SQL Server connection info                     |
| sql-adsi        | [server] [ADSI_linkedserver] [opt: port] [opt: database] [opt: linkedserver] [opt: impersonate] | Obtain ADSI creds from ADSI linked server                |
| sql-agentcmd    | [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] | Execute a system command using agent jobs                |
| sql-agentstatus | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate SQL agent status and jobs                      |
| sql-checkrpc    | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate RPC status of linked servers                   |
| sql-clr         | [server] [dll_path] [function] [opt: database] [opt: linkedserver] [opt: impersonate] | Load and execute .NET assembly in a stored procedure     |
| sql-columns     | [server] [table] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate columns within a table                         |
| sql-databases   | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate databases on a server                          |
| sql-disableclr  | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Disable CLR integration                                  |
| sql-disableole  | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Disable OLE Automation Procedures                        |
| sql-disablerpc  | [server] [linkedserver] [opt: database] [opt: impersonate]   | Disable RPC and RPC out on a linked server               |
| sql-disablexp   | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Disable xp_cmdshell                                      |
| sql-enableclr   | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enable CLR integration                                   |
| sql-enableole   | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enable OLE Automation Procedures                         |
| sql-enablerpc   | [server] [linkedserver] [opt: database] [opt: impersonate]   | Enable RPC and RPC out on a linked server                |
| sql-enablexp    | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enable xp_cmdshell                                       |
| sql-impersonate | [server] [opt: database]                                     | Enumerate users that can be impersonated                 |
| sql-info        | [server] [opt: database]                                     | Gather information about the SQL server                  |
| sql-links       | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate linked servers                                 |
| sql-olecmd      | [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] | Execute a system command using OLE automation procedures |
| sql-query       | [server] [query] [opt: database] [opt: linkedserver] [opt: impersonate] | Execute a custom SQL query                               |
| sql-rows        | [server] [table] [opt: database] [opt: linkedserver] [opt: impersonate] | Get the count of rows in a table                         |
| sql-search      | [server] [search] [opt: database] [opt: linkedserver] [opt: impersonate] | Search a table for a column name                         |
| sql-smb         | [server] [\\listener] [opt: database] [opt: linkedserver] [opt: impersonate] | Coerce NetNTLM auth via xp_dirtree                       |
| sql-tables      | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate tables within a database                       |
| sql-users       | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Enumerate users with database access                     |
| sql-whoami      | [server] [opt: database] [opt: linkedserver] [opt: impersonate] | Gather logged in user, mapped user and roles             |
| sql-xpcmd       | [server] [command] [opt: database] [opt: linkedserver] [opt: impersonate] | Execute a system command via xp_cmdshell                 |

## Credits

- [SQL-BOF](https://github.com/Tw1sm/SQL-BOF) by [@Tw1sm](https://github.com/Tw1sm)

