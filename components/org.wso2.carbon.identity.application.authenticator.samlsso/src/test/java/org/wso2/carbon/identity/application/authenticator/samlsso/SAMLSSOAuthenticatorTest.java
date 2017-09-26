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

import org.apache.commons.io.FileUtils;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml2.core.NameIDType;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit test cases for SAMLSSOAuthenticator
 */
public class SAMLSSOAuthenticatorTest {

    @Mock
    private HttpServletRequest mockedHttpServletRequest;
    @Mock
    private HttpServletResponse mockedAuthnHttpServletResponse;
    @Mock
    private HttpServletResponse mockedLogoutHttpServletResponse;
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

    private SAMLSSOAuthenticator samlssoAuthenticator = new SAMLSSOAuthenticator();

    @BeforeClass
    public void initTest() throws SocketException {

        MockitoAnnotations.initMocks(this);
        FileBasedConfigurationBuilder.getInstance(TestUtils.getFilePath("application-authentication.xml"));
    }

    @Test(priority = 1)
    public void testCanHandle() {

        when(mockedHttpServletRequest.getParameter("SAMLResponse")).thenReturn("SAMLResponse");
        Assert.assertTrue(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Failed to handle for valid input");
    }

    @Test(priority = 2)
    public void testCanHandleFalse() {

        when(mockedHttpServletRequest.getParameter("SAMLResponse")).thenReturn(null);
        Assert.assertFalse(samlssoAuthenticator.canHandle(mockedHttpServletRequest), "Able to handle for invalid " +
                "input");
    }

    @Test(priority = 3)
    public void testInitiatePostAuthenticationRequest() throws Exception {

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
        Assert.assertTrue(postPage.contains("SAMLRequest"), "Failed to build the SAML request");
        Assert.assertTrue(postPage.contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 4)
    public void testInitiateRedirectAuthenticationRequest() throws Exception {

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
        Assert.assertTrue(captor.getValue().contains("SAMLRequest"), "Failed to build the SAML request");
        Assert.assertTrue(captor.getValue().contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 5)
    public void testInitiatePostLogoutRequest() throws LogoutFailedException, IOException {

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
        Assert.assertTrue(postPage.contains("SAMLRequest"), "Failed to build the SAML request");
        Assert.assertTrue(postPage.contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 6)
    public void testInitiateRedirectLogoutRequest() throws LogoutFailedException, IOException {

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
        Assert.assertTrue(captor.getValue().contains("SAMLRequest"), "Failed to build the SAML request");
        Assert.assertTrue(captor.getValue().contains("RelayState"), "Failed to add relay state");
    }

    @Test(priority = 7)
    public void testGetContextIdentifierFromSessionDataKey() {

        when(mockedHttpServletRequest.getParameter("sessionDataKey")).thenReturn("123456789");
        Assert.assertEquals("123456789", samlssoAuthenticator.getContextIdentifier(mockedHttpServletRequest), "Failed" +
                " to retrive context identifier from sessionDataKey");
    }

    @Test(priority = 8)
    public void testGetContextIdentifierFromRelayState() {

        when(mockedHttpServletRequest.getParameter("sessionDataKey")).thenReturn(null);
        when(mockedHttpServletRequest.getParameter("RelayState")).thenReturn("987654321");
        Assert.assertEquals("987654321", samlssoAuthenticator.getContextIdentifier(mockedHttpServletRequest), "Failed" +
                " to retrieve context identifier from RelayState");
    }

    @Test(priority = 9)
    public void testGetFriendlyName() {

        Assert.assertEquals(SSOConstants.AUTHENTICATOR_FRIENDLY_NAME, samlssoAuthenticator.getFriendlyName(), "Failed" +
                " to retrieve connector friendly name");
    }

    @Test(priority = 10)
    public void testGetName() {

        Assert.assertEquals(SSOConstants.AUTHENTICATOR_NAME, samlssoAuthenticator.getName(), "Failed to retrieve " +
                "connector name");
    }

    @Test(expectedExceptions = {UnsupportedOperationException.class}, priority = 11)
    public void testProcessLogoutResponse() throws LogoutFailedException, UnsupportedOperationException {

        samlssoAuthenticator.processLogoutResponse(mockedHttpServletRequest, mockedLogoutHttpServletResponse,
                mockedAuthenticationContext);
    }
}
