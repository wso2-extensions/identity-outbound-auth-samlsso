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

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.commons.dbcp.BasicDataSource;
import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCache;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityContextCache;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_NAME;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_URL;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SESSION_INDEX;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SAML2_SLO_POST_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockServiceURLBuilder;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_SLO_REQUEST_ACCEPTED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL;

/**
 * Unit test cases for SAMLLogoutRequestProcessor
 */
@WithCarbonHome
@PrepareForTest({IdentityDatabaseUtil.class, IdentityProviderManager.class, SAMLSSOAuthenticatorServiceDataHolder.class,
        IdentityCoreServiceComponent.class, AuthenticationRequestCache.class, IdentityContextCache.class,
        ServiceURLBuilder.class})
@WithH2Database(files = {"dbscripts/h2.sql"})
public class SAMLLogoutRequestProcessorTest extends PowerMockTestCase {

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private static final String DB_NAME = "testSAMLSLO";
    private static final String SAML_INDEX = "94911684-8ef8-407b-bc59-e435b6270858";

    @Mock
    private SAMLLogoutRequest mockedRequest;

    @Mock
    private IdentityProviderManager mockedIdPManager;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private SAMLSSOAuthenticatorServiceDataHolder mockedAuthenticator;

    @Mock
    private ConfigurationContextService mockedService;

    @Mock
    private ConfigurationContext mockedContext;

    @Mock
    private AxisConfiguration mockedConfig;

    @Mock
    private AuthenticationRequestCache mockedCache;

    @Mock
    private IdentityContextCache mockedIdentityCache;

    @Test
    public void testProcess() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        when(mockedRequest.isPost()).thenReturn(true);
        PowerMockito.when(mockedRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).
                thenReturn(SAML2_SLO_POST_REQUEST);

        setupDatabase();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getConnection(DB_NAME));

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(mockedIdPManager);

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(IDP_NAME);

        FederatedAuthenticatorConfig config = new FederatedAuthenticatorConfig();
        Property[] properties = new Property[6];

        Property property = new Property();
        property.setName(IS_SLO_REQUEST_ACCEPTED);
        property.setValue("true");
        properties[0] = property;

        property = new Property();
        property.setName(SP_ENTITY_ID);
        property.setValue("lacalhost");
        properties[1] = property;

        property = new Property();
        property.setName(IS_AUTHN_RESP_SIGNED);
        property.setValue("false");
        properties[2] = property;

        property = new Property();
        property.setName(INCLUDE_CERT);
        property.setValue("false");
        properties[3] = property;

        property = new Property();
        property.setName(IS_LOGOUT_REQ_SIGNED);
        property.setValue("false");
        properties[4] = property;

        property = new Property();
        property.setName(SSO_URL);
        property.setValue(IDP_URL);
        properties[5] = property;

        config.setProperties(properties);
        idp.setDefaultAuthenticatorConfig(config);

        when(mockedIdPManager.getIdPByName(IDP_NAME, SUPER_TENANT_DOMAIN)).thenReturn(idp);

        mockStatic(SAMLSSOAuthenticatorServiceDataHolder.class);
        when(SAMLSSOAuthenticatorServiceDataHolder.getInstance()).thenReturn(mockedAuthenticator);
        when(mockedAuthenticator.getRealmService()).thenReturn(mockedRealmService);

        mockStatic(IdentityCoreServiceComponent.class);
        when(IdentityCoreServiceComponent.getConfigurationContextService()).thenReturn(mockedService);
        when(mockedService.getServerConfigContext()).thenReturn(mockedContext);
        when(mockedContext.getAxisConfiguration()).thenReturn(mockedConfig);

        mockStatic(AuthenticationRequestCache.class);
        when(AuthenticationRequestCache.getInstance()).thenReturn(mockedCache);

        mockStatic(IdentityContextCache.class);
        when(IdentityContextCache.getInstance()).thenReturn(mockedIdentityCache);

        mockServiceURLBuilder();
        assertNotNull(processor.process(mockedRequest));
    }

    private void setupDatabase() throws Exception {

        initiateH2Base(DB_NAME, getFilePath("h2.sql"));

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);

            String sql = "INSERT INTO IDN_FED_AUTH_SESSION_MAPPING " +
                    "(IDP_SESSION_ID, SESSION_ID, IDP_NAME,  AUTHENTICATOR_ID, PROTOCOL_TYPE) VALUES ( '" +
                    SAML_INDEX + "' , '" + INBOUND_SESSION_INDEX + "' , '" + IDP_NAME + "' , " +
                    "'samlssoAuthenticator', 'samlsso');";
            PreparedStatement statement = connection1.prepareStatement(sql);
            statement.execute();
        }

        try (Connection connection1 = getConnection(DB_NAME)) {
            prepareConnection(connection1, false);
            String query = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID=?";
            PreparedStatement statement2 = connection1.prepareStatement(query);
            statement2.setString(1, "94911684-8ef8-407b-bc59-e435b6270858");
            ResultSet resultSet = statement2.executeQuery();
            String result = null;
            if (resultSet.next()) {
                result = resultSet.getString("SESSION_ID");
            }
            assertEquals(INBOUND_SESSION_INDEX, result, "Failed to handle for valid input");
        }
    }

    private void prepareConnection(Connection connection1, boolean b) {

        mockStatic(IdentityDatabaseUtil.class);
        PowerMockito.when(IdentityDatabaseUtil.getDBConnection(b)).thenReturn(connection1);
    }

    private void initiateH2Base(String databaseName, String scriptPath) throws Exception {

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

    private void closeH2Base(String databaseName) throws Exception {

        BasicDataSource dataSource = dataSourceMap.get(databaseName);
        if (dataSource != null) {
            dataSource.close();
        }
    }

    private static Connection getConnection(String database) throws SQLException {

        if (dataSourceMap.get(database) != null) {
            return dataSourceMap.get(database).getConnection();
        }
        throw new RuntimeException("No datasource initiated for database: " + database);
    }

    private static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dbscripts", fileName)
                    .toString();
        }
        throw new IllegalArgumentException("DB Script file name cannot be empty.");
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base(DB_NAME);
    }
}

