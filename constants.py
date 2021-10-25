ERR_REC_NOT_SELECTED = "Please select a record"
ERR_MISSING_PARAMS = "Name, telephone, email and description are required"

DB_NAME = "database.db"

QUERY_INSERT = "INSERT INTO agenda VALUES(NULL, ?, ?, ?, ?);"
QUERY_DELETE = "DELETE FROM agenda WHERE name = ?;"
QUERY_UPDATE = "UPDATE agenda SET name = ?, telephone = ?, email = ?, description = ?  WHERE name = ? AND telephone = ? AND email = ? AND description = ?;"
QUERY_GET    = "SELECT * FROM agenda ORDER BY name DESC;"

QUERY_INSERT_CRYPTO = "INSERT INTO cryptostore VALUES(?, ?, ?);"
QUERY_UPDATE_CRYPTO = "UPDATE cryptostore SET iv = ?, key_hmac = ? WHERE iv = ? AND key_hmac = ?;"
QUERY_GET_CRYPTO    = "SELECT * FROM cryptostore ORDER BY ID DESC;"

