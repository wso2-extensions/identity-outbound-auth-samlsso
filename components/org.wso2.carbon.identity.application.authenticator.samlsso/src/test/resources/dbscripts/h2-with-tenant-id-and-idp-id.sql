CREATE TABLE IF NOT EXISTS IDN_FED_AUTH_SESSION_MAPPING (
    ID INTEGER AUTO_INCREMENT,
	IDP_SESSION_ID VARCHAR(255) NOT NULL,
	SESSION_ID VARCHAR(255) NOT NULL,
	IDP_NAME VARCHAR(255) NOT NULL,
	AUTHENTICATOR_ID VARCHAR(255),
	PROTOCOL_TYPE VARCHAR(255),
	TENANT_ID INTEGER NOT NULL DEFAULT 0,
	IDP_ID INTEGER NOT NULL DEFAULT 0,
	TIME_CREATED TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY(ID)
);