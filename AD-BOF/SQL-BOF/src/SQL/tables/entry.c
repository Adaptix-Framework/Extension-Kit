#include "base.c"
#include "bofdefs.h"
#include "sql.c"

void CheckTables(char *server, char *database, char *link, char *impersonate, char *user, char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLHDBC dbc = NULL;
  char *query = NULL;
  SQLRETURN ret;

  if (link == NULL) {
    dbc = ConnectToSqlServerAuth(&env, server, database, user, password);
  } else {
    dbc = ConnectToSqlServerAuth(&env, server, NULL, user, password);
  }

  if (dbc == NULL) {
    goto END;
  }

  if (link == NULL) {
    internal_printf("[*] Enumerating tables in the %s database on %s\n\n", database, server);
  } else {
    internal_printf( "[*] Enumerating tables in the %s database on %s via %s\n\n", database, link, server);
  }

  ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Error allocating statement handle\n");
    goto END;
  }

  char *prefix = "SELECT * FROM ";
  char *suffix = ".INFORMATION_SCHEMA.TABLES;";

  size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(database) + MSVCRT$strlen(suffix) + 1;
  query = (char *)intAlloc(totalSize * sizeof(char));

  MSVCRT$strcpy(query, prefix);
  MSVCRT$strncat(query, database, totalSize - MSVCRT$strlen(query) - 1);
  MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

  if (!HandleQuery(stmt, (SQLCHAR *)query, link, impersonate, FALSE)) {
    goto END;
  }

  PrintQueryResults(stmt, TRUE);

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
  char *user;
  char *password;

  datap parser;
  BeaconDataParse(&parser, Buffer, Length);

  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  link = BeaconDataExtract(&parser, NULL);
  impersonate = BeaconDataExtract(&parser, NULL);
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

  CheckTables(server, database, link, impersonate, user, password);

  printoutput(TRUE);
};