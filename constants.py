ERR_REC_NOT_SELECTED = "Please select a record"
ERR_MISSING_PARAMS = "Name, telephone, email and description are required"
ERR_DATA_NOT_VERIFIED ="Some data are not verified, please consider checking it"

DB_NAME = "database.db"

QUERY_INSERT = "INSERT INTO agenda VALUES(NULL, ?, ?, ?, ?);"
QUERY_DELETE = "DELETE FROM agenda WHERE name = ?;"
QUERY_UPDATE = "UPDATE agenda SET name = ?, telephone = ?, email = ?, description = ?  WHERE name = ? AND telephone = ? AND email = ? AND description = ?;"
QUERY_GET    = "SELECT * FROM agenda;"

QUERY_INSERT_CRYPTO = "INSERT INTO cryptostore VALUES(NULL, ?, ?);"
QUERY_DELETE_CRYPTO = "DELETE FROM cryptostore WHERE 1=1;"
QUERY_GET_CRYPTO    = "SELECT * FROM cryptostore;"

QUERY_INSERT_HMAC = "INSERT INTO hmac VALUES (NULL ,?, ?, ?, ?);"
QUERY_DELETE_HMAC = "DELETE FROM hmac WHERE 1=1;"
QUERY_GET_HMAC = "SELECT * FROM hmac;"

