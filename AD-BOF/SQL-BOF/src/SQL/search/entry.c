#include "base.c"
#include "bofdefs.h"
#include "sql.c"

void Search(char *server, char *database, char *link, char *impersonate,
            char *keyword, char *user, char *password) {
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
    internal_printf(
        "[*] Searching for columns containing \"%s\" in %s on %s\n\n", keyword,
        database, server);
  } else {
    internal_printf(
        "[*] Searching for columns containing \"%s\" in %s on %s via %s\n\n",
        keyword, database, link, server);
  }

  //
  // allocate statement handle
  //
  ret = ODBC32$SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
  if (!SQL_SUCCEEDED(ret)) {
    internal_printf("[!] Error allocating statement handle\n");
    goto END;
  }

  //
  // Construct query
  //
  char *prefix = "SELECT table_name, column_name FROM ";
  char *middle = ".information_schema.columns WHERE column_name LIKE '%";
  char *suffix = "%';";

  size_t totalSize = MSVCRT$strlen(prefix) + MSVCRT$strlen(database) +
                     MSVCRT$strlen(middle) + MSVCRT$strlen(keyword) +
                     MSVCRT$strlen(suffix) + 1;
  query = (char *)intAlloc(totalSize * sizeof(char));

  MSVCRT$strcpy(query, prefix);
  MSVCRT$strncat(query, database, totalSize - MSVCRT$strlen(query) - 1);
  MSVCRT$strncat(query, middle, totalSize - MSVCRT$strlen(query) - 1);
  MSVCRT$strncat(query, keyword, totalSize - MSVCRT$strlen(query) - 1);
  MSVCRT$strncat(query, suffix, totalSize - MSVCRT$strlen(query) - 1);

  //
  // Run the query
  //
  if (!HandleQuery(stmt, (SQLCHAR *)query, link, impersonate, TRUE)) {
    goto END;
  }

  PrintQueryResults(stmt, TRUE);

END:
  if (query != NULL)
    intFree(query);
  ODBC32$SQLCloseCursor(stmt);
  DisconnectSqlServer(env, dbc, stmt);
}

#ifdef BOF
VOID go(IN PCHAR Buffer, IN ULONG Length) {
  char *server;
  char *database;
  char *link;
  char *impersonate;
  char *keyword;
  char *user;
  char *password;

  //
  // parse beacon args
  //
  datap parser;
  BeaconDataParse(&parser, Buffer, Length);

  server = BeaconDataExtract(&parser, NULL);
  database = BeaconDataExtract(&parser, NULL);
  link = BeaconDataExtract(&parser, NULL);
  impersonate = BeaconDataExtract(&parser, NULL);
  keyword = BeaconDataExtract(&parser, NULL);
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

  Search(server, database, link, impersonate, keyword, user, password);

  printoutput(TRUE);
};

#else

int main() {
  internal_printf("============ BASE TEST ============\n\n");
  Search("castelblack.north.sevenkingdoms.local", "master", NULL, NULL, "idle",
         NULL, NULL);

  internal_printf("\n\n============ IMPERSONATE TEST ============\n\n");
  Search("castelblack.north.sevenkingdoms.local", "master", NULL, "sa", "idle",
         NULL, NULL);

  internal_printf("\n\n============ LINK TEST ============\n\n");
  Search("castelblack.north.sevenkingdoms.local", "master", "BRAAVOS", NULL,
         "idle", NULL, NULL);
}

#endif
