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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.
        AnalyticsAttributes.SESSION_ID;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.FED_IDP_ID;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IDP_NAME;

/**
 * DAO class to handle the federated idp initiated logout flow related DB operations.
 */
public class SessionInfoDAO {

    private static final String SESSION_ID_COLUMN_LABEL = "SESSION_ID";
    private static final String IDP_NAME_COLUMN_LABEL = "IDP_NAME";
    private static final String IDP_ID_COLUMN_LABEL = "IDP_ID";

    private static final String SQL_SELECT_BY_IDP_SESSION_ID
            = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID = ?";
    private static final String SQL_SELECT_BY_IDP_SESSION_ID_AND_TENANT_ID
            = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID = ? AND TENANT_ID = ?";

    private static final Log log = LogFactory.getLog(SessionInfoDAO.class);

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param samlIndex Session Index of the SAML Logout Request.
     * @return Map of session details.
     * @throws SAMLLogoutException If DB execution fails.
     */
    public Map<String, String> getSessionDetails(String samlIndex) throws SAMLLogoutException {

        return getSessionDetails(SQL_SELECT_BY_IDP_SESSION_ID, samlIndex, -1, false);
    }

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param samlIndex Session Index of the SAML Logout Request.
     * @return Map of session details.
     * @throws SAMLLogoutException If DB execution fails.
     */
    public Map<String, String> getSessionDetails(String samlIndex, int tenantId) throws SAMLLogoutException {

        return getSessionDetails(SQL_SELECT_BY_IDP_SESSION_ID_AND_TENANT_ID, samlIndex, tenantId, true);
    }

    private Map<String, String> getSessionDetails(String query, String samlIndex, int tenantId, boolean useTenantId) throws SAMLLogoutException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, samlIndex);
            if (useTenantId) {
                preparedStatement.setInt(2, tenantId);
            }
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                Map<String, String> sessionDetails = new HashMap<>();
                if (resultSet.next()) {
                    sessionDetails.put(SESSION_ID, resultSet.getString(SESSION_ID_COLUMN_LABEL));
                    sessionDetails.put(IDP_NAME, resultSet.getString(IDP_NAME_COLUMN_LABEL));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved session details: " + sessionDetails +
                            " for federated idp session index: " + samlIndex);
                }
                return sessionDetails;
            }
        } catch (SQLException e) {
            throw new SAMLLogoutException("Unable to retrieve session details from the database with SAML Index: "
                    + samlIndex, e);
        }
    }

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param samlIndex Session Index of the SAML Logout Request.
     * @return Map of session details including federated idp id.
     * @throws SAMLLogoutException If DB execution fails.
     */
    public List<Map<String, String>> getSessionDetailsIncludingIdpId(String samlIndex) throws SAMLLogoutException {

        return getSessionDetailsIncludingIdpId(SQL_SELECT_BY_IDP_SESSION_ID, samlIndex, -1, false);
    }

    /**
     * Retrieve the session details of a given SAML Index from the database.
     *
     * @param samlIndex Session Index of the SAML Logout Request.
     * @return Map of session details including federated idp id.
     * @throws SAMLLogoutException If DB execution fails.
     */
    public List<Map<String, String>> getSessionDetailsIncludingIdpId(String samlIndex, int tenantId)
            throws SAMLLogoutException {

        return getSessionDetailsIncludingIdpId(SQL_SELECT_BY_IDP_SESSION_ID_AND_TENANT_ID, samlIndex, tenantId, true);
    }

    private List<Map<String, String>> getSessionDetailsIncludingIdpId(String query, String samlIndex, int tenantId,
                                                                      boolean useTenantId) throws SAMLLogoutException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, samlIndex);
            if (useTenantId) {
                preparedStatement.setInt(2, tenantId);
            }
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                List<Map<String, String>> sessionDetailsList = new ArrayList<>();
                while (resultSet.next()) {
                    Map<String, String> sessionDetails = new HashMap<>();
                    sessionDetails.put(SESSION_ID, resultSet.getString(SESSION_ID_COLUMN_LABEL));
                    sessionDetails.put(IDP_NAME, resultSet.getString(IDP_NAME_COLUMN_LABEL));
                    sessionDetails.put(FED_IDP_ID, resultSet.getString(IDP_ID_COLUMN_LABEL));
                    sessionDetailsList.add(sessionDetails);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Retrieved session details list: " + sessionDetailsList +
                            " for federated idp session index: " + samlIndex);
                }
                return sessionDetailsList;
            }
        } catch (SQLException e) {
            throw new SAMLLogoutException("Unable to retrieve session details from the database with SAML Index: "
                    + samlIndex, e);
        }
    }
}
