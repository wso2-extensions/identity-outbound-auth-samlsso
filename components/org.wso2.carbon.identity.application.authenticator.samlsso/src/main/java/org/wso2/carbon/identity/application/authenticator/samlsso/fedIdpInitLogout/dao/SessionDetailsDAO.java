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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/**
 * DAO class to handle the federated idp initiated logout flow related DB operations.
 */
public class SessionDetailsDAO {

    private static final Log log = LogFactory.getLog(SessionDetailsDAO.class);

    /**
     * return the session details of a given saml index.
     *
     * @param sessionIndex Extracted saml index of the logout request
     * @return session details of given saml index
     * @throws SQLException
     */

    public Map<String, String> getSessionDetails(String sessionIndex) throws SQLException {

        Map<String, String> sessionDetails = new HashMap<>();
        String query = "SELECT * FROM IDN_FEDERATED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID =?";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, sessionIndex);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    sessionDetails.put("sessionID", resultSet.getString("SESSION_ID"));
                    sessionDetails.put("idpID", resultSet.getString("IDP_ID"));
                }
            }
        } catch (SQLException e) {
            throw new SQLException("Unable to read session details from the database with saml id: " + sessionIndex, e);
        }
        return sessionDetails;
    }
}
