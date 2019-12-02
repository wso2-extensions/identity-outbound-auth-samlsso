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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.util.HashMap;
import java.util.Map;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.InboundRequestData.INBOUND_LOGOUT_REQUEST;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.*;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Unit test cases for SAMLLogoutRequestProcessor
 */

public class SAMLLogoutRequestProcessorTest extends PowerMockTestCase {

    @Mock
    private SAMLMessageContext mockedSAMLMessageContext;

    @Mock
    private IdentityProvider mockedIdentityProvider;

    @Mock
    private IdentityRequest mockedIdentityRequest;

    @Mock
    private SAMLLogoutRequest mocke;

    private SAMLLogoutRequestProcessor samlLogoutRequestProcessor = new SAMLLogoutRequestProcessor();
    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private static final String DB_NAME = "testSAMLSLO";
    private static final String create_table ="CREATE TABLE IF NOT EXISTS IDN_FEDERATED_AUTH_SESSION_MAPPING (" +
            "IDP_SESSION_ID VARCHAR(255) NOT NULL,SESSION_ID VARCHAR(255) NOT NULL, IDP_NAME VARCHAR(255) NOT NULL," +
            "AUTHENTICATOR_ID VARCHAR(255),PROTOCOL_TYPE VARCHAR(255),TIME_CREATED TIMESTAMP NOT NULL DEFAULT " +
            "CURRENT_TIMESTAMP," + "PRIMARY KEY(IDP_SESSION_ID) );";

//    @Test
//    public void testCanHandle(){
//        assertTrue(samlLogoutRequestProcessor.canHandle(mockedIdentityRequest));
//    }

    @DataProvider(name = "logoutRequestBuilderDataProvider")
    public Object[][] logoutRequestBuilderData() {

        return new Object[][]{

                {
                        INBOUND_LOGOUT_REQUEST.getRequestData()
                },
        };
    }

    @Test(expectedExceptions = SAMLSSOException.class)
    public void testProcessRedirectLogoutRequest() throws Exception{
        
        when(mocke.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(SAML2_SLO_POST_REQUEST);
        when(mocke.isPost()).thenReturn(Boolean.TRUE);
        setupDatabase();;


        //samlLogoutRequestProcessor.process(mocke);



        Map<String, String> mockedFedIdPConfigs = new HashMap<>();
        mockedFedIdPConfigs.put(IS_SLO_REQUEST_ACCEPTED, "true");
        mockedFedIdPConfigs.put(SSO_URL, "https:localhost/9444/samlsso");
        mockedFedIdPConfigs.put(SP_ENTITY_ID, "localhost");
        mockedFedIdPConfigs.put(IS_AUTHN_RESP_SIGNED, "false");
        mockedFedIdPConfigs.put(INCLUDE_CERT,"false");
        when(mockedSAMLMessageContext.getFedIdPConfigs()).thenReturn(mockedFedIdPConfigs);
        when(mockedSAMLMessageContext.getFederatedIdP()).thenReturn(mockedIdentityProvider);
        when(mockedIdentityProvider.getIdentityProviderName()).thenReturn("IdP1");


        when(mockedSAMLMessageContext.getSAMLLogoutRequest()).thenReturn(mocke);
        when(mocke.isPost()).thenReturn(Boolean.TRUE);
        when(mocke.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(SAML2_LOGOUT_POST_REQUEST);

    }

    private void setupDatabase() throws Exception{
        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
        createTable();
        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, true);

            String sql = "INSERT INTO IDN_FEDERATED_AUTH_SESSION_MAPPING " +
                    "            +(IDP_SESSION_ID, SESSION_ID, IDP_NAME,  AUTHENTICATOR_ID, PROTOCOL_TYPE) VALUES " +
                    "('94911684-8ef8-407b-bc59-e435b6270858', '1234', 'secondary', 'samlssoAuthenticator', 'samlsso');";
            PreparedStatement statement = connection1.prepareStatement(sql);
            statement.execute();
        }
    }

    private void prepareConnection(Connection connection1, boolean b) {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(b)).thenReturn(connection1);
    }

    protected void initiateH2Base(String databaseName, String scriptPath) throws Exception {

        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUsername("username");
        dataSource.setPassword("password");
        dataSource.setUrl("jdbc:h2:mem:test" + databaseName);
        try (Connection connection = dataSource.getConnection()) {
            connection.createStatement().executeUpdate("RUNSCRIPT FROM '" + scriptPath + "'");
        }
        dataSourceMap.put(databaseName, dataSource);
    }

    protected void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    public static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }
    private void createTable() throws Exception {

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            PreparedStatement statement = connection1.prepareStatement(create_table);
            statement.execute();
        }

    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbScripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    @AfterClass
    public void tearDown() throws Exception {
        closeH2Base(DB_NAME);
    }




}
