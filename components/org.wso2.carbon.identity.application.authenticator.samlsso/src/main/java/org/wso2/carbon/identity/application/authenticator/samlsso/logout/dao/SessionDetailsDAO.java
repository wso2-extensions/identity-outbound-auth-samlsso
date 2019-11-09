/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.IDP_ID;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.SESSION_ID;

/**
 * DAO class to handle the federated idp initiated logout flow related DB operations.
 */
public class SessionDetailsDAO {

    private static final Log log = LogFactory.getLog(SessionDetailsDAO.class);

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param sessionIndex Session Index of the SAML Logout Request.
     * @return Map of session details.
     * @throws SAMLIdentityException If DB execution fails.
     */
    public Map<String, String> getSessionDetails(String sessionIndex) throws SAMLIdentityException {

        final String query = "SELECT * FROM IDN_FEDERATED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID =?";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, sessionIndex);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                Map<String, String> sessionDetails = new HashMap<>();
                if (resultSet.next()) {
                    sessionDetails.put(SESSION_ID, resultSet.getString("SESSION_ID"));
                    sessionDetails.put(IDP_ID, resultSet.getString("IDP_ID"));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved session index: " + resultSet.getString("SESSION_ID") +
                            " from federated idp session index: " + sessionIndex);
                }

                return sessionDetails;
            }
        } catch (SQLException e) {
            String notification = "Unable to retrieve session details from the database with SAML Index: "
                    + sessionIndex;
            if (log.isDebugEnabled()) {
                log.debug(notification, e);
            }
            throw new SAMLIdentityException(notification, e);
        }
    }
}
