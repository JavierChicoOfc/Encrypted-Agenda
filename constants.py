ERR_REC_NOT_SELECTED = "Please select a record"
ERR_MISSING_PARAMS = "Name, telephone, email and description are required"
ERR_DATA_NOT_VERIFIED ="Some data are not verified, please consider checking it"

DATA_VERIFIED = "All the data is verified"

DB_NAME = "database.db"

QUERY_INSERT = "INSERT INTO agenda VALUES(NULL, ?, ?, ?, ?);"
QUERY_DELETE = "DELETE FROM agenda WHERE name = ?;"
QUERY_UPDATE = "UPDATE agenda SET name = ?, telephone = ?, email = ?, description = ?  WHERE name = ? AND telephone = ? AND email = ? AND description = ?;"
QUERY_GET    = "SELECT * FROM agenda;"

QUERY_INSERT_IVSTORE = "INSERT INTO ivstore VALUES(NULL, ?, ?, ?, ?);"
QUERY_DELETE_IVSTORE = "DELETE FROM ivstore WHERE 1=1;"

QUERY_INSERT_SALT_HMAC_STORE = "INSERT INTO salt_hmac_store VALUES(NULL, ?, ?, ?, ?);"
QUERY_DELETE_SALT_HMAC_STORE = "DELETE FROM salt_hmac_store WHERE 1=1;"

QUERY_GET_IVSTORE         = "SELECT * FROM ivstore;"
QUERY_GET_SALT_HMAC_STORE = "SELECT * FROM salt_hmac_store;"

QUERY_GET_CRYPTO          = "SELECT * FROM cryptostore;"
QUERY_DELETE_CRYPTO       = "DELETE FROM cryptostore WHERE 1=1;"
QUERT_INSERT_CRYPTO       = "INSERT INTO cryptostore VALUES(NULL, ?);"

QUERY_INSERT_HMAC = "INSERT INTO hmac VALUES (NULL ,?, ?, ?, ?);"
QUERY_DELETE_HMAC = "DELETE FROM hmac WHERE 1=1;"
QUERY_GET_HMAC = "SELECT * FROM hmac;"

