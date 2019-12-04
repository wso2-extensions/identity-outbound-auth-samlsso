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
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLLogoutException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.
        AnalyticsAttributes.SESSION_ID;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IDP_NAME;

/**
 * DAO class to handle the federated idp initiated logout flow related DB operations.
 */
public class SessionInfoDAO {

    private static final Log log = LogFactory.getLog(SessionInfoDAO.class);

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param samlIndex Session Index of the SAML Logout Request.
     * @return Map of session details.
     * @throws SAMLLogoutException If DB execution fails.
     */
    public Map<String, String> getSessionDetails(String samlIndex) throws SAMLLogoutException {

        final String query = "SELECT * FROM IDN_FEDERATED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID = ?";

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, samlIndex);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                Map<String, String> sessionDetails = new HashMap<>();
                if (resultSet.next()) {
                    sessionDetails.put(SESSION_ID, resultSet.getString("SESSION_ID"));
                    sessionDetails.put(IDP_NAME, resultSet.getString("IDP_NAME"));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved session index: " + resultSet.getString("SESSION_ID") +
                            " for federated idp session index: " + samlIndex);
                }
                return sessionDetails;
            }
        } catch (SQLException e) {
            throw new SAMLLogoutException("Unable to retrieve session details from the database with SAML Index: "
                    + samlIndex, e);
        }
    }
}
