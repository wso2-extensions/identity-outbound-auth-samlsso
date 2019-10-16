package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class SessionDetailsDAO {

    private static final Log log = LogFactory.getLog(SessionDetailsDAO.class);

    //get session id connected to idp session id from the database
    public Map<String,String> getSessionDetails(String sessionIndex)  {

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;

        Map<String, String> sessionDetails = new HashMap<>();
        String query = "SELECT * FROM IDN_FEDERATED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID =?";

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, sessionIndex);
            resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                sessionDetails.put("sessionID", resultSet.getString("SESSION_ID"));
                sessionDetails.put("idpID", resultSet.getString("IDP_ID"));
            }
        } catch (SQLException e) {
            log.error("Unable to read session details from the database with saml id: " + sessionIndex, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
        return sessionDetails;

    }
}
