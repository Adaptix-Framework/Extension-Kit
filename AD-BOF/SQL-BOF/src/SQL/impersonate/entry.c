#include "base.c"
#include "bofdefs.h"
#include "sql.c"

void CheckImpersonate(char *server, char *database, char *user,
                      char *password) {
  SQLHENV env = NULL;
  SQLHSTMT stmt = NULL;
  SQLRETURN ret;

  SQLHDBC dbc = ConnectToSqlServerAuth(&env, server, database, user, password);

  if (dbc == NULL) {
    goto END;
  }

  internal_printf("[*] Enumerating users that can be impersonated on %s\n\n",
                  server);

  //
  // allocate statement handle
  //
  ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Error allocating statement handle\n");
    goto END;
  }

  //
  // Run the query
  //
  SQLCHAR *query =
      (SQLCHAR *)"SELECT distinct b.name FROM sys.server_permissions a "
                 "INNER JOIN sys.server_principals b ON a.grantor_principal_id "
                 "= b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
  if (!ExecuteQuery(stmt, query)) {
    goto END;
  }
  PrintQueryResults(stmt, TRUE);

END:
  ODBC32$SQLCloseCursor(stmt);
  DisconnectSqlServer(env, dbc, stmt);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
  char *server = NULL;
  char *database = NULL;
  char *user = NULL;
  char *password = NULL;

  //
  // parse beacon args
  //
  datap parser;
  BeaconDataParse(&parser, Buffer, Length);

  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  user = BeaconDataExtract(&parser, NULL);
  password = BeaconDataExtract(&parser, NULL);

  server = *server == 0 ? "localhost" : server;
  database = *database == 0 ? "master" : database;
  user = *user == 0 ? NULL : user;
  password = *password == 0 ? NULL : password;

  if (!bofstart()) {
    return;
  }

  CheckImpersonate(server, database, user, password);

  printoutput(TRUE);
};

#else

int main() {
  internal_printf("============ BASE TEST ============\n\n");
  CheckImpersonate("castelblack.north.sevenkingdoms.local", "master", NULL,
                   NULL);
}

#endif
