/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.NameIDType;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.io.File;
import java.io.PrintWriter;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.xpath.XPathFactory;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.doCallRealMethod;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockDOMImplementationRegistry;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockDocumentBuilderFactory;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockXMLInputFactory;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockXPathFactory;

/**
 * Unit test cases for SAMLSSOAuthenticator
 */
@PowerMockIgnore({"javax.xml.datatype.*"})
@PrepareForTest({XPathFactory.class, XMLInputFactory.class, DocumentBuilderFactory.class, IdentityUtil.class,
        DOMImplementationRegistry.class})
public class SAMLSSOAuthenticatorTest {

    public static final String INBOUND_QUERY_KEY = "inbound_query_key";
    public static final String INBOUND_QUERY_VALUE = "inbound_query_value";
    public static final String DYNAMIC_QUERY_PARAM = "dynamic_query_param";
    @Mock
    private HttpServletRequest mockedHttpServletRequest;
    @Mock
    private HttpServletResponse mockedAuthnHttpServletResponse;
    @Mock
    private HttpServletResponse mockedLogoutHttpServletResponse;
    @Mock
    private HttpServletRequest mockedReturnedHttpServletRequest;
    @Mock
    private HttpServletResponse mockedReturnedHttpServletResponse;
    @Mock
    private AuthenticationContext mockedAuthenticationContext;
    @Mock
    private IdentityProvider mockedIdentityProvider;
    @Mock
    private ExternalIdPConfig mockedExternalIdPConfig;
    @Mock
    private AuthenticationRequest mockedAuthenticationRequest;
    @Mock
    private HttpSession mockedHttpSession;
    @Mock
    private UserRealm mockedUserRealm;
    @Mock
    private RealmService mockedRealmService;
    @Mock
    private UserStoreManager mockedUserStoreManager;
    @Mock
    private RealmConfiguration mockedRealmConfiguration;
    @Mock
    private DOMImplementationRegistry mockedDomImplementationRegistry;

    private SAMLSSOAuthenticator samlssoAuthenticator = new SAMLSSOAuthenticator();

    @BeforeClass
    public void initTest() throws SocketException {

        mockXMLInputFactory();
        FileBasedConfigurationBuilder.getInstance(TestUtils.getFilePath("application-authentication.xml"));
    }

    @Test(priority = 1)
    public void testCanHandle() {

        when(mockedHttpServletRequest.getParameter("SAMLResponse")).thenReturn("SAMLResponse");
        assertTrue(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Failed to handle for valid input");
    }

    @Test(priority = 1)
    public void testCanHandleArtifactBinding() {

        when(mockedHttpServletRequest.getParameter(TestConstants.HTTP_POST_PARAM_SAML_ART)).thenReturn(
                TestConstants.HTTP_POST_PARAM_SAML_ART);
        assertTrue(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Failed to handle for valid input");
    }

    @Test(priority = 2)
    public void testCanHandleFalse() {

        when(mockedHttpServletRequest.getParameter("SAMLResponse")).thenReturn(null);
        assertFalse(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Able to handle for invalid input");
    }

    @Test(priority = 2)
    public void testCanHandleArtifactBindingFalse() {

        when(mockedHttpServletRequest.getParameter(TestConstants.HTTP_POST_PARAM_SAML_ART)).thenReturn(null);
        when(mockedHttpServletRequest.getParameter(TestConstants.HTTP_POST_PARAM_SAML2_RESP)).thenReturn(null);
        assertFalse(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Able to handle for invalid input");
    }

    @Test(priority = 3)
    public void testInitiatePostAuthenticationRequest() throws Exception {

        mockXPathFactory();
        mockDocumentBuilderFactory();
        mockDOMImplementationRegistry(mockedDomImplementationRegistry);

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL, TestConstants.IDP_URL);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD,
                SSOConstants.POST);
        when(mockedAuthenticationContext.getContextIdentifier()).thenReturn(TestConstants.RELAY_STATE);
        when(mockedAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);

        when(mockedExternalIdPConfig.getIdentityProvider()).thenReturn(mockedIdentityProvider);
        when(mockedAuthenticationContext.getExternalIdP()).thenReturn(mockedExternalIdPConfig);

        when(mockedAuthenticationRequest.getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))
                .thenReturn(new String[]{TestConstants.SAML2_POST_REQUEST});
        when(mockedAuthenticationRequest.isPost()).thenReturn(Boolean.TRUE);
        when(mockedAuthenticationContext.getAuthenticationRequest()).thenReturn(mockedAuthenticationRequest);

        PrintWriter out = new PrintWriter("auth-request.txt");
        when(mockedAuthnHttpServletResponse.getWriter()).thenReturn(out);

        samlssoAuthenticator.initiateAuthenticationRequest(mockedHttpServletRequest, mockedAuthnHttpServletResponse,
                mockedAuthenticationContext);
        out.flush();
        String postPage = FileUtils.readFileToString(new File("auth-request.txt"), "UTF-8");
        assertTrue(postPage.contains("SAMLRequest"), "Failed to build the SAML request");
        assertTrue(postPage.contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 4)
    public void testInitiateRedirectAuthenticationRequest() throws Exception {

        mockXPathFactory();
        mockDocumentBuilderFactory();

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL, TestConstants.IDP_URL);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD,
                SSOConstants.REDIRECT);
        when(mockedAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockedAuthenticationContext.getContextIdentifier()).thenReturn(TestConstants.RELAY_STATE);

        when(mockedExternalIdPConfig.getIdentityProvider()).thenReturn(mockedIdentityProvider);
        when(mockedAuthenticationContext.getExternalIdP()).thenReturn(mockedExternalIdPConfig);

        when(mockedAuthenticationRequest.getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))
                .thenReturn(new String[]{TestConstants.SAML2_REDIRECT_REQUEST});
        when(mockedAuthenticationRequest.isPost()).thenReturn(Boolean.FALSE);
        when(mockedAuthenticationContext.getAuthenticationRequest()).thenReturn(mockedAuthenticationRequest);

        samlssoAuthenticator.initiateAuthenticationRequest(mockedHttpServletRequest, mockedAuthnHttpServletResponse,
                mockedAuthenticationContext);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(mockedAuthnHttpServletResponse).sendRedirect(captor.capture());
        assertTrue(captor.getValue().contains("SAMLRequest"), "Failed to build the SAML request");
        assertTrue(captor.getValue().contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 5)
    public void testInitiatePostLogoutRequest() throws Exception {

        mockXPathFactory();
        mockDocumentBuilderFactory();
        mockDOMImplementationRegistry(mockedDomImplementationRegistry);

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL, TestConstants.IDP_URL);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD,
                SSOConstants.POST);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED, "true");
        when(mockedAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);

        when(mockedHttpSession.getAttribute(SSOConstants.LOGOUT_USERNAME)).thenReturn("SomeUser");
        when(mockedHttpSession.getAttribute(SSOConstants.LOGOUT_SESSION_INDEX)).thenReturn("123456789");
        when(mockedHttpSession.getAttribute(SSOConstants.NAME_QUALIFIER)).thenReturn(NameIDType.UNSPECIFIED);
        when(mockedHttpSession.getAttribute(SSOConstants.SP_NAME_QUALIFIER)).thenReturn(NameIDType.UNSPECIFIED);
        when(mockedHttpServletRequest.getSession()).thenReturn(mockedHttpSession);

        PrintWriter out = new PrintWriter("logout-request.txt");
        when(mockedLogoutHttpServletResponse.getWriter()).thenReturn(out);

        samlssoAuthenticator.initiateLogoutRequest(mockedHttpServletRequest, mockedLogoutHttpServletResponse,
                mockedAuthenticationContext);
        out.flush();
        String postPage = FileUtils.readFileToString(new File("logout-request.txt"), "UTF-8");
        assertTrue(postPage.contains("SAMLRequest"), "Failed to build the SAML request");
        assertTrue(postPage.contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 6)
    public void testInitiateRedirectLogoutRequest() throws Exception {

        mockDocumentBuilderFactory();

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL,
                "https://localhost:9443/samlsso");
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD,
                SSOConstants.REDIRECT);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED, "true");
        when(mockedAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);

        when(mockedHttpSession.getAttribute(SSOConstants.LOGOUT_USERNAME)).thenReturn("SomeUser");
        when(mockedHttpSession.getAttribute(SSOConstants.LOGOUT_SESSION_INDEX)).thenReturn("123456789");
        when(mockedHttpSession.getAttribute(SSOConstants.NAME_QUALIFIER)).thenReturn(NameIDType.UNSPECIFIED);
        when(mockedHttpSession.getAttribute(SSOConstants.SP_NAME_QUALIFIER)).thenReturn(NameIDType.UNSPECIFIED);
        when(mockedHttpServletRequest.getSession()).thenReturn(mockedHttpSession);

        samlssoAuthenticator.initiateLogoutRequest(mockedHttpServletRequest, mockedLogoutHttpServletResponse,
                mockedAuthenticationContext);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(mockedLogoutHttpServletResponse).sendRedirect(captor.capture());
        assertTrue(captor.getValue().contains("SAMLRequest"), "Failed to build the SAML request");
        assertTrue(captor.getValue().contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 7)
    public void testGetContextIdentifierFromSessionDataKey() {

        when(mockedHttpServletRequest.getParameter("sessionDataKey")).thenReturn("123456789");
        assertEquals("123456789", samlssoAuthenticator.getContextIdentifier(mockedHttpServletRequest), "Failed" +
                " to retrive context identifier from sessionDataKey");
    }

    @Test(priority = 8)
    public void testGetContextIdentifierFromRelayState() {

        when(mockedHttpServletRequest.getParameter("sessionDataKey")).thenReturn(null);
        when(mockedHttpServletRequest.getParameter("RelayState")).thenReturn("987654321");
        assertEquals("987654321", samlssoAuthenticator.getContextIdentifier(mockedHttpServletRequest), "Failed" +
                " to retrieve context identifier from RelayState");
    }

    @Test(priority = 9)
    public void testGetFriendlyName() {

        assertEquals(SSOConstants.AUTHENTICATOR_FRIENDLY_NAME, samlssoAuthenticator.getFriendlyName(), "Failed" +
                " to retrieve connector friendly name");
    }

    @Test(priority = 10)
    public void testGetName() {

        assertEquals(SSOConstants.AUTHENTICATOR_NAME, samlssoAuthenticator.getName(), "Failed to retrieve " +
                "connector name");
    }

    @Test(expectedExceptions = {UnsupportedOperationException.class}, priority = 11)
    public void testProcessLogoutResponse() throws LogoutFailedException, UnsupportedOperationException {

        samlssoAuthenticator.processLogoutResponse(mockedHttpServletRequest, mockedLogoutHttpServletResponse,
                mockedAuthenticationContext);
    }

    @Test
    public void testProcessAuthenticationResponse() throws Exception {

        mockXPathFactory();
        mockDocumentBuilderFactory();
        mockDOMImplementationRegistry(mockedDomImplementationRegistry);

        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(mockedRealmService);

        when(mockedRealmService.getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(mockedUserRealm);
        when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.getRealmConfiguration()).thenReturn(mockedRealmConfiguration);
        when(mockedRealmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR))
                .thenReturn(",");

        when(mockedExternalIdPConfig.getIdentityProvider()).thenReturn(mockedIdentityProvider);
        when(mockedAuthenticationContext.getExternalIdP()).thenReturn(mockedExternalIdPConfig);

        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = issueInstant.toDateTime(DateTimeZone.UTC).plusMillis(5 * 60 * 1000);
        String samlResponse = TestConstants.SAML_RESPONSE.replace("NotOnOrAfter=\"2017-10-06T14:18:59.302Z\"",
                "NotOnOrAfter=\"" + notOnOrAfter + "\"");
        when(mockedReturnedHttpServletRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_RESP))
                .thenReturn(new String(Base64.encodeBase64(samlResponse.getBytes())));

        when(mockedReturnedHttpServletRequest.getSession()).thenReturn(mockedHttpSession);
        when(mockedReturnedHttpServletRequest.getSession(false)).thenReturn(mockedHttpSession);
        when(mockedHttpSession.getAttribute("username")).thenReturn("admin");

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID,
                "SAMLSSOIdentity");
        when(mockedAuthenticationContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);

        doCallRealMethod().when(mockedAuthenticationContext).setSubject(any(AuthenticatedUser.class));
        doCallRealMethod().when(mockedAuthenticationContext).getSubject();

        samlssoAuthenticator.processAuthenticationResponse(mockedReturnedHttpServletRequest,
                mockedReturnedHttpServletResponse, mockedAuthenticationContext);

        assertEquals("admin", mockedAuthenticationContext.getSubject().getAuthenticatedSubjectIdentifier(), "Failed " +
                "retrive the authenticated user from the SAML2 response");
    }

    @DataProvider(name = "inboundRequestQueryParamProvider")
    public Object[][] provideDummyData() {

        return new Object[][]{
                {new String[]{INBOUND_QUERY_VALUE}, null, INBOUND_QUERY_VALUE},
                {new String[]{StringUtils.EMPTY}, null, StringUtils.EMPTY},
                {null, INBOUND_QUERY_VALUE, INBOUND_QUERY_VALUE},
                {null, null, StringUtils.EMPTY}
        };
    }

    @Test(dataProvider = "inboundRequestQueryParamProvider")
    public void testDynamicQueryParams(String[] inboundQueryParamValues, String requestQueryParamValue,
                                       String exceptedQueryParamValue) throws Exception {

        mockXPathFactory();
        mockDocumentBuilderFactory();
        mockDOMImplementationRegistry(mockedDomImplementationRegistry);

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL, TestConstants.IDP_URL);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD, SSOConstants.POST);
        authenticatorProperties.put(FrameworkConstants.QUERY_PARAMS,
                DYNAMIC_QUERY_PARAM + "={" + INBOUND_QUERY_KEY + "}");

        AuthenticationContext context = new AuthenticationContext();
        context.setContextIdentifier(TestConstants.RELAY_STATE);
        context.setAuthenticatorProperties(authenticatorProperties);

        when(mockedExternalIdPConfig.getIdentityProvider()).thenReturn(mockedIdentityProvider);
        context.setExternalIdP(mockedExternalIdPConfig);

        when(mockedAuthenticationRequest.getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))
                .thenReturn(new String[]{TestConstants.SAML2_POST_REQUEST});
        when(mockedAuthenticationRequest.isPost()).thenReturn(Boolean.TRUE);
        when(mockedAuthenticationRequest.getRequestQueryParam(INBOUND_QUERY_KEY)).thenReturn(inboundQueryParamValues);

        if (requestQueryParamValue != null) {
            when(mockedHttpServletRequest.getParameter(INBOUND_QUERY_KEY)).thenReturn(requestQueryParamValue);
        } else {
            when(mockedHttpServletRequest.getParameter(INBOUND_QUERY_KEY)).thenReturn(null);
        }

        context.setAuthenticationRequest(mockedAuthenticationRequest);

        PrintWriter out = new PrintWriter("auth-request.txt");
        when(mockedAuthnHttpServletResponse.getWriter()).thenReturn(out);

        samlssoAuthenticator.initiateAuthenticationRequest(mockedHttpServletRequest, mockedAuthnHttpServletResponse, context);
        out.flush();

        String resolvedQueryParams = context.getAuthenticatorProperties().get(FrameworkConstants.QUERY_PARAMS);
        Map<String, String> queryParamMap = SSOUtils.getQueryMap(resolvedQueryParams);

        String resolvedDynamicQueryParamValue = queryParamMap.get(DYNAMIC_QUERY_PARAM);
        assertEquals(resolvedDynamicQueryParamValue, exceptedQueryParamValue);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }
}
