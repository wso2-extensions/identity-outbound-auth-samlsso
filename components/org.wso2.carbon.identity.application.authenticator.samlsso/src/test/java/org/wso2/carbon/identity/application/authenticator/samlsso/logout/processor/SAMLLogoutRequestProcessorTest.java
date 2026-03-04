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
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCache;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityContextCache;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLLogoutException;
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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_NAME;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_URL;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SESSION_INDEX;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SAML2_SLO_POST_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockServiceURLBuilder;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID;
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
@WithH2Database(files = {"dbscripts/h2.sql", "dbscripts/h2-with-tenant-id.sql",
        "dbscripts/h2-with-tenant-id-and-idp-id.sql"})
public class SAMLLogoutRequestProcessorTest {

    private static Map<String, BasicDataSource> dataSourceMap = new HashMap<>();
    private static final String DB_NAME = "testSAMLSLO";
    private static final String DB_WITH_TENANT_ID_NAME = "testSAMLSLOWithTenantId";
    private static final String DB_NAME_WITH_TENANT_ID_AND_IDP_ID_COLUMNS = "testSAMLSLOWithTenantAndIdpId";
    private static final String SAML_INDEX = "94911684-8ef8-407b-bc59-e435b6270858";

    private static final String IDP_ID = "2";
    private static final String TENANT_ID = "1";

    private static final String INSERT_SQL =  "INSERT INTO IDN_FED_AUTH_SESSION_MAPPING " +
            "(IDP_SESSION_ID, SESSION_ID, IDP_NAME, AUTHENTICATOR_ID, PROTOCOL_TYPE) VALUES ( '" +
            SAML_INDEX + "' , '" + INBOUND_SESSION_INDEX + "' , '" + IDP_NAME + "' , " +
            "'samlssoAuthenticator', 'samlsso');";
    private static final String INSERT_SQL_WITH_TENANT_ID = "INSERT INTO IDN_FED_AUTH_SESSION_MAPPING " +
            "(IDP_SESSION_ID, SESSION_ID, IDP_NAME, AUTHENTICATOR_ID, PROTOCOL_TYPE, TENANT_ID) VALUES ( '" +
            SAML_INDEX + "' , '" + INBOUND_SESSION_INDEX + "' , '" + IDP_NAME + "' , " +
            "'samlssoAuthenticator', 'samlsso', '" + TENANT_ID + "');";
    private static final String INSERT_SQL_WITH_TENANT_ID_AND_IDP_ID = "INSERT INTO IDN_FED_AUTH_SESSION_MAPPING " +
            "(IDP_SESSION_ID, SESSION_ID, IDP_NAME, AUTHENTICATOR_ID, PROTOCOL_TYPE, TENANT_ID, IDP_ID) VALUES ( '" +
            SAML_INDEX + "' , '" + INBOUND_SESSION_INDEX + "' , '" + IDP_NAME + "' , " +
            "'samlssoAuthenticator', 'samlsso', '" + TENANT_ID + "', '" + IDP_ID + "');";
    private static final String SELECT_SQL = "SELECT * FROM IDN_FED_AUTH_SESSION_MAPPING WHERE IDP_SESSION_ID=?";

    @Mock
    private SAMLLogoutRequest mockedRequest;

    // Don't store IdentityProviderManager mock as a field to avoid class redefinition issues in Java 21

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

    @BeforeMethod
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
    }
        
    @Test
    public void testProcess() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        mockRequest();
        setupDatabase(DB_NAME, "h2.sql", INSERT_SQL);
        
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockIdentityDatabaseUtil(DB_NAME);
             MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockIdentityProviderManager(getMockIdp());
             MockedStatic<SAMLSSOAuthenticatorServiceDataHolder> samlssoAuthenticatorServiceDataHolderMock = mockSAMLSSOAuthenticatorServiceDataHolder();
             MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponentMock = mockIdentityCoreServiceComponent();
             MockedStatic<AuthenticationRequestCache> authenticationRequestCacheMock = mockAuthenticationRequestCache();
             MockedStatic<IdentityContextCache> identityContextCacheMock = mockIdentityContextCache();
             MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = mockServiceURLBuilder()) {
            
            assertNotNull(processor.process(mockedRequest));
        }
    }

    @Test
    public void testProcessWithTenantId() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        mockRequest();
        setupDatabase(DB_WITH_TENANT_ID_NAME, "h2-with-tenant-id.sql", INSERT_SQL_WITH_TENANT_ID);
        
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockIdentityDatabaseUtil(DB_WITH_TENANT_ID_NAME);
             MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockIdentityProviderManager(getMockIdp());
             MockedStatic<SAMLSSOAuthenticatorServiceDataHolder> samlssoAuthenticatorServiceDataHolderMock = mockSAMLSSOAuthenticatorServiceDataHolder();
             MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponentMock = mockIdentityCoreServiceComponent();
             MockedStatic<AuthenticationRequestCache> authenticationRequestCacheMock = mockAuthenticationRequestCache();
             MockedStatic<IdentityContextCache> identityContextCacheMock = mockIdentityContextCache();
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockFrameworkUtils(true, false);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockIdentityTenantUtil();
             MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = mockServiceURLBuilder()) {
            
            assertNotNull(processor.process(mockedRequest));
        }
    }

    @Test(expectedExceptions = SAMLLogoutException.class)
    public void testProcessWithTenantIdSLONotAccepted() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        mockRequest();
        
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockIdentityDatabaseUtil(DB_WITH_TENANT_ID_NAME);
             MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockIdentityProviderManager(getMockIdpWithoutSlo());
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockFrameworkUtils(true, false);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockIdentityTenantUtil();
             MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = mockServiceURLBuilder()) {
            
            assertNotNull(processor.process(mockedRequest));
        }
    }

    @Test
    public void testProcessWithTenantIdAndIdpId() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        mockRequest();
        setupDatabase(DB_NAME_WITH_TENANT_ID_AND_IDP_ID_COLUMNS, "h2-with-tenant-id-and-idp-id.sql",
                INSERT_SQL_WITH_TENANT_ID_AND_IDP_ID);
        
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockIdentityDatabaseUtil(DB_NAME_WITH_TENANT_ID_AND_IDP_ID_COLUMNS);
             MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockIdentityProviderManager(getMockIdp());
             MockedStatic<SAMLSSOAuthenticatorServiceDataHolder> samlssoAuthenticatorServiceDataHolderMock = mockSAMLSSOAuthenticatorServiceDataHolder();
             MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponentMock = mockIdentityCoreServiceComponent();
             MockedStatic<AuthenticationRequestCache> authenticationRequestCacheMock = mockAuthenticationRequestCache();
             MockedStatic<IdentityContextCache> identityContextCacheMock = mockIdentityContextCache();
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockFrameworkUtils(true, true);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockIdentityTenantUtil();
             MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = mockServiceURLBuilder()) {
            
            assertNotNull(processor.process(mockedRequest));
        }
    }

    @Test(expectedExceptions = SAMLLogoutException.class)
    public void testProcessWithTenantIdAndIdpIdSLONotAccepted() throws Exception {

        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        mockRequest();
        
        try (MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockIdentityDatabaseUtil(DB_NAME_WITH_TENANT_ID_AND_IDP_ID_COLUMNS);
             MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockIdentityProviderManager(getMockIdpWithoutSlo());
             MockedStatic<FrameworkUtils> frameworkUtilsMock = mockFrameworkUtils(true, true);
             MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockIdentityTenantUtil();
             MockedStatic<ServiceURLBuilder> serviceURLBuilderMock = mockServiceURLBuilder()) {
            
            assertNotNull(processor.process(mockedRequest));
        }
    }

    private void mockRequest() {

        when(mockedRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).
                thenReturn(SAML2_SLO_POST_REQUEST);
        when(mockedRequest.isPost()).thenReturn(true);
    }

    private MockedStatic<IdentityDatabaseUtil> mockIdentityDatabaseUtil(String dbName) throws SQLException {

        MockedStatic<IdentityDatabaseUtil> identityDatabaseUtilMock = mockStatic(IdentityDatabaseUtil.class);
        identityDatabaseUtilMock.when(() -> IdentityDatabaseUtil.getDBConnection(false)).thenReturn(getConnection(dbName));
        return identityDatabaseUtilMock;
    }

    private MockedStatic<IdentityProviderManager> mockIdentityProviderManager(IdentityProvider mockIdp) throws IdentityProviderManagementException {

        // Create a fresh mock instance for each test
        IdentityProviderManager mockedIdPManager = mock(IdentityProviderManager.class, withSettings().lenient());
        
        MockedStatic<IdentityProviderManager> identityProviderManagerMock = mockStatic(IdentityProviderManager.class);
        identityProviderManagerMock.when(IdentityProviderManager::getInstance).thenReturn(mockedIdPManager);
        when(mockedIdPManager.getIdPByName(IDP_NAME, SUPER_TENANT_DOMAIN)).thenReturn(mockIdp);
        when(mockedIdPManager.getIdPById(IDP_ID, SUPER_TENANT_DOMAIN)).thenReturn(mockIdp);
        return identityProviderManagerMock;
    }

    private MockedStatic<SAMLSSOAuthenticatorServiceDataHolder> mockSAMLSSOAuthenticatorServiceDataHolder() {

        MockedStatic<SAMLSSOAuthenticatorServiceDataHolder> samlssoAuthenticatorServiceDataHolderMock = mockStatic(SAMLSSOAuthenticatorServiceDataHolder.class);
        samlssoAuthenticatorServiceDataHolderMock.when(SAMLSSOAuthenticatorServiceDataHolder::getInstance).thenReturn(mockedAuthenticator);
        when(mockedAuthenticator.getRealmService()).thenReturn(mockedRealmService);
        return samlssoAuthenticatorServiceDataHolderMock;
    }

    private MockedStatic<IdentityCoreServiceComponent> mockIdentityCoreServiceComponent() {

        MockedStatic<IdentityCoreServiceComponent> identityCoreServiceComponentMock = mockStatic(IdentityCoreServiceComponent.class);
        identityCoreServiceComponentMock.when(IdentityCoreServiceComponent::getConfigurationContextService).thenReturn(mockedService);
        when(mockedService.getServerConfigContext()).thenReturn(mockedContext);
        when(mockedContext.getAxisConfiguration()).thenReturn(mockedConfig);
        return identityCoreServiceComponentMock;
    }

    private MockedStatic<AuthenticationRequestCache> mockAuthenticationRequestCache() {

        MockedStatic<AuthenticationRequestCache> authenticationRequestCacheMock = mockStatic(AuthenticationRequestCache.class);
        authenticationRequestCacheMock.when(AuthenticationRequestCache::getInstance).thenReturn(mockedCache);
        return authenticationRequestCacheMock;
    }

    private MockedStatic<IdentityContextCache> mockIdentityContextCache() {

        MockedStatic<IdentityContextCache> identityContextCacheMock = mockStatic(IdentityContextCache.class);
        identityContextCacheMock.when(IdentityContextCache::getInstance).thenReturn(mockedIdentityCache);
        return identityContextCacheMock;
    }

    private MockedStatic<FrameworkUtils> mockFrameworkUtils(boolean isTenantIdColumnAvailable, boolean isIdpIdColumnAvailable) {

        MockedStatic<FrameworkUtils> frameworkUtilsMock = mockStatic(FrameworkUtils.class);
        frameworkUtilsMock.when(FrameworkUtils::isTenantIdColumnAvailableInFedAuthTable).thenReturn(isTenantIdColumnAvailable);
        frameworkUtilsMock.when(FrameworkUtils::isIdpIdColumnAvailableInFedAuthTable).thenReturn(isIdpIdColumnAvailable);
        return frameworkUtilsMock;
    }

    private MockedStatic<IdentityTenantUtil> mockIdentityTenantUtil() {

        MockedStatic<IdentityTenantUtil> identityTenantUtilMock = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMock.when(() -> IdentityTenantUtil.getTenantId(SUPER_TENANT_DOMAIN)).thenReturn(Integer.parseInt(TENANT_ID));
        return identityTenantUtilMock;
    }

    private IdentityProvider getMockIdp() {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(IDP_NAME);

        FederatedAuthenticatorConfig config = new FederatedAuthenticatorConfig();
        Property[] properties = new Property[7];

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

        property = new Property();
        property.setName(IDP_ENTITY_ID);
        property.setValue("localhost");
        properties[6] = property;

        config.setProperties(properties);
        idp.setDefaultAuthenticatorConfig(config);

        return idp;
    }

    private IdentityProvider getMockIdpWithoutSlo() {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName(null);

        FederatedAuthenticatorConfig config = new FederatedAuthenticatorConfig();
        Property[] properties = new Property[1];

        Property property = new Property();
        property.setName(IS_SLO_REQUEST_ACCEPTED);
        property.setValue("false");
        properties[0] = property;

        config.setProperties(properties);
        idp.setDefaultAuthenticatorConfig(config);

        return idp;
    }

    private void setupDatabase(String dbName, String initFileName, String insertSql) throws Exception {

        initiateH2Base(dbName, getFilePath(initFileName));

        try (Connection connection1 = getConnection(dbName)) {
            PreparedStatement statement = connection1.prepareStatement(insertSql);
            statement.execute();
        }

        try (Connection connection1 = getConnection(dbName)) {
            PreparedStatement statement2 = connection1.prepareStatement(SELECT_SQL);
            statement2.setString(1, SAML_INDEX);
            ResultSet resultSet = statement2.executeQuery();
            String result = null;
            if (resultSet.next()) {
                result = resultSet.getString("SESSION_ID");
            }
            assertEquals(INBOUND_SESSION_INDEX, result, "Failed to handle for valid input");
        }
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
        closeH2Base(DB_WITH_TENANT_ID_NAME);
        closeH2Base(DB_NAME_WITH_TENANT_ID_AND_IDP_ID_COLUMNS);
    }
}

