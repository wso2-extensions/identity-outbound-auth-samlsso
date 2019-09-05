package org.wso2.carbon.identity.application.authenticator.samlsso.dao;


import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;



public class SessionDetailsDAO {

    private static final Log log = LogFactory.getLog(SessionDetailsDAO.class);

    public SessionDetailsDAO() {
    }

    // get session ID related to the SAML Index in SAML logout request

    public String getSessionID(String sessionIndex) throws SAMLSSOException {

        String sessionID = null;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        String query = "SELECT SESSION_ID FROM IDN_FEDERATED_AUTH_USER_SESSION_MAPPING WHERE IDP_SESSION_ID =?";

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, sessionIndex);
            resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                sessionID = resultSet.getString("SESSION_ID");
            }

            if (sessionID.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No Session ID relevant to the SAML Index: " + sessionIndex);
                }
                return null;
            }
        } catch (SQLException e) {
            log.error("Unable to read session id from the database with saml id: " + sessionIndex, e);
            throw new SAMLSSOException("Unable to read session id with saml id:" + sessionIndex + " on database ", e);

        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
        return sessionID;

    }
}
