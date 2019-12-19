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

package org.wso2.carbon.identity.application.authenticator.samlsso.manager;

import org.apache.commons.lang.StringUtils;
import org.mockito.Mock;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.RequestData;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLDecoder;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPathFactory;

import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.InboundRequestData.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockDOMImplementationRegistry;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockDocumentBuilderFactory;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockXPathFactory;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.ACS_URL;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Unit test cases for DefaultSAML2SSOManager
 */
@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityUtil.class, DocumentBuilderFactory.class,
        KeyStoreManager.class, DOMImplementationRegistry.class, XPathFactory.class, FrameworkUtils.class})
public class DefaultSAML2SSOManagerTest {

    @Mock
    private HttpServletRequest mockedHttpServletRequest;

    @Mock
    private AuthenticationContext mockedAuthenticationContext;

    @Mock
    private IdentityProvider mockedIdentityProvider;

    @Mock
    private FileBasedConfigurationBuilder mockedFileBasedConfigurationBuilder;

    @Mock
    private AuthenticatorConfig mockedAuthenticatorConfig;

    @Mock
    private AuthenticationRequest mockedAuthenticationRequest;

    @Mock
    private RealmService mockedRealmService;

    @Mock
    private KeyStoreManager mockedSuperTenantKeyStoreManager;

    @Mock
    private TenantManager mockedTenantManager;

    @Mock
    private DOMImplementationRegistry mockedDomImplementationRegistry;

    @Mock
    private SignatureImpl mockedSignatureImpl;

    private KeyStore keyStore;

    private Key key;

    private Certificate certificate;

    private X509Credential x509CredentialImpl;

    @BeforeClass
    public void initTest() throws Exception {
    }

    @Test
    public void testDoBootstrap() throws NoSuchFieldException, IllegalAccessException {

        DefaultSAML2SSOManager.doBootstrap();

        Field bootStrappedField = DefaultSAML2SSOManager.class.getDeclaredField("bootStrapped");
        bootStrappedField.setAccessible(true);
        assertTrue(bootStrappedField.getBoolean(null));
    }

    @Test
    public void testInit() throws SAMLSSOException, NoSuchFieldException, IllegalAccessException {

        DefaultSAML2SSOManager defaultSAML2SSOManager = new DefaultSAML2SSOManager();
        Map<String, String> properties = new HashMap<>();
        IdentityProvider identityProvider = new IdentityProvider();
        defaultSAML2SSOManager.init(SUPER_TENANT_DOMAIN_NAME, properties, identityProvider);

        Field tenantDomainField = defaultSAML2SSOManager.getClass().getDeclaredField("tenantDomain");
        tenantDomainField.setAccessible(true);
        assertEquals(SUPER_TENANT_DOMAIN_NAME, tenantDomainField.get(defaultSAML2SSOManager),
                "Failed to set tenant domain.");

        Field propertiesField = defaultSAML2SSOManager.getClass().getDeclaredField("properties");
        propertiesField.setAccessible(true);
        assertEquals(properties, propertiesField.get(defaultSAML2SSOManager), "Failed to set properties.");

        Field identityProviderField = defaultSAML2SSOManager.getClass().getDeclaredField("identityProvider");
        identityProviderField.setAccessible(true);
        assertEquals(identityProvider, identityProviderField.get(defaultSAML2SSOManager),
                "Failed to set identity provider");
    }

    @DataProvider(name = "redirectRequestBuilderDataProvider")
    public Object[][] redirectRequestBuilderData() {

        return new Object[][]{
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_SIGNED_CERT_NOT_INCLUDED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_UNSIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_NULL_SP.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_EMPTRY_SP.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_FORCE_AUTH_YES.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_FORCE_AUTH_AS_REQUEST.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_EMPTY_PROTOCOL_BINDING.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_PROTOCOL_BINDING_TRUE.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_PROTOCOL_BINDING_FALSE.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_WITH_ACS_INDEX.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_INCLUDE_NAME_ID_POLICY.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_NOT_INCLUDE_NAME_ID_POLICY.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_REDIRECT_REQUEST_INCLUDE_POST_PARAM.getRequestData()
                },
        };
    }

    @Test(dataProvider = "redirectRequestBuilderDataProvider")
    public void testBuildRequest(boolean isLogout, String tenantDomain, Object inboundRequestData,
                                 Object outboundRequestData) throws Exception {

        DefaultSAML2SSOManager.doBootstrap();
        when(mockedAuthenticationContext.getContextIdentifier()).thenReturn(TestConstants.RELAY_STATE);

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);

        mockXPathFactory();

        RequestData requestData = (RequestData) outboundRequestData;

        Map<String, String> authenticatorProperties = new HashMap<>();

        setParametersForBuildAuthnRequest(isLogout, requestData, (RequestData) inboundRequestData,
                authenticatorProperties);

        DefaultSAML2SSOManager defaultSAML2SSOManager = new DefaultSAML2SSOManager();
        defaultSAML2SSOManager.init(tenantDomain, authenticatorProperties, mockedIdentityProvider);
        String generatedRequest = defaultSAML2SSOManager.buildRequest(mockedHttpServletRequest, false, false,
                TestConstants.IDP_URL, mockedAuthenticationContext);
        assertNotNull(generatedRequest, "Failed to build federated authentication request.");

        String decodedRequest = getDecodedSAMLRedirectRequest(generatedRequest);
        assertNotNull(decodedRequest, "Failed to decode the generated request.");

        XMLObject xmlObject = TestUtils.unmarshall(decodedRequest);
        if (!isLogout) {
            assertAuthnRequest((AuthnRequest) xmlObject, requestData);
        }
    }

    @Test(dataProvider = "redirectRequestBuilderDataProvider")
    public void testBuildRequestWithIdpAccessURL(boolean isLogout, String tenantDomain, Object inboundRequestData,
                                                 Object outboundRequestData) throws Exception {

        DefaultSAML2SSOManager.doBootstrap();
        when(mockedAuthenticationContext.getContextIdentifier()).thenReturn(TestConstants.RELAY_STATE);
        mockXPathFactory();
        RequestData requestData = (RequestData) outboundRequestData;
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(ACS_URL, TestConstants.IDP_ACS_URL);
        setParametersForBuildAuthnRequest(isLogout, requestData, (RequestData) inboundRequestData,
                authenticatorProperties);
        DefaultSAML2SSOManager defaultSAML2SSOManager = new DefaultSAML2SSOManager();
        defaultSAML2SSOManager.init(tenantDomain, authenticatorProperties, mockedIdentityProvider);
        String generatedRequest = defaultSAML2SSOManager.buildRequest(mockedHttpServletRequest, false, false,
                TestConstants.IDP_URL, mockedAuthenticationContext);
        assertNotNull(generatedRequest, "Failed to build federated authentication request.");

        String decodedRequest = getDecodedSAMLRedirectRequest(generatedRequest);
        assertNotNull(decodedRequest, "Failed to decode the generated request.");

        XMLObject xmlObject = TestUtils.unmarshall(decodedRequest);
        if (!isLogout) {
            assertAuthnRequest((AuthnRequest) xmlObject, requestData);
        }
    }

    @DataProvider(name = "postRequestBuilderDataProvider")
    public Object[][] postRequestBuilderData() {

        return new Object[][]{

                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_REDIRECT_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_SIGNED_CERT_NOT_INCLUDED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_UNSIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_SIGNED.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_NULL_SP.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_EMPTRY_SP.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_FORCE_AUTH_YES.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_FORCE_AUTH_AS_REQUEST.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_EMPTY_PROTOCOL_BINDING.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_PROTOCOL_BINDING_TRUE.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_PROTOCOL_BINDING_FALSE.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_AUTH_CONFIG_AVAILABLE.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_AUTH_CONFIG_ACS_EMPTY.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_WITH_ACS_INDEX.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_INCLUDE_NAME_ID_POLICY.getRequestData()
                },
                {
                        false,
                        SUPER_TENANT_DOMAIN_NAME,
                        INBOUND_POST_REQUEST.getRequestData(),
                        OUTBOUND_POST_REQUEST_NOT_INCLUDE_NAME_ID_POLICY.getRequestData()
                },
        };
    }

    @Test(dataProvider = "postRequestBuilderDataProvider")
    public void buildPostRequest(boolean isLogout, String tenantDomain, Object inboundRequestData,
                                 Object outboundRequestData) throws Exception {

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);

        DefaultSAML2SSOManager.doBootstrap();
        when(mockedAuthenticationContext.getContextIdentifier()).thenReturn(TestConstants.RELAY_STATE);

        mockXPathFactory();

        RequestData requestData = (RequestData) outboundRequestData;

        Map<String, String> authenticatorProperties = new HashMap<>();

        setParametersForBuildAuthnRequest(isLogout, requestData, (RequestData) inboundRequestData,
                authenticatorProperties);

        DefaultSAML2SSOManager defaultSAML2SSOManager = new DefaultSAML2SSOManager();
        defaultSAML2SSOManager.init(tenantDomain, authenticatorProperties, mockedIdentityProvider);
        String generatedRequest = defaultSAML2SSOManager.buildPostRequest(mockedHttpServletRequest, false, false,
                TestConstants.IDP_URL, mockedAuthenticationContext);
        assertNotNull(generatedRequest, "Failed to build federated authentication request.");

        String decodedRequest = getDecodedSAMLPostRequest(generatedRequest);
        assertNotNull(decodedRequest, "Failed to decode the generated request.");

        XMLObject xmlObject = TestUtils.unmarshall(decodedRequest);
        if (!isLogout) {

            AuthnRequest authnRequest = (AuthnRequest) xmlObject;
            assertAuthnRequest(authnRequest, requestData);

            if (requestData.isSignRequest()) {
                assertNotNull(authnRequest.getSignature(), "Failed to sign the request");
                if (requestData.isIncludeCertProperty()) {
                    assertNotNull(authnRequest.getSignature().getKeyInfo(), "Failed to add signing cert data");
                }
            } else {
                assertNull(authnRequest.getSignature(), "Invalid signature for request");
            }
        }
    }

    @DataProvider(name = "logoutRequestBuilderDataProvider")
    public Object[][] logoutRequestBuilderData() {

        return new Object[][]{

                {
                        INBOUND_LOGOUT_REQUEST.getRequestData()
                },
        };
    }

    @Test(dataProvider = "logoutRequestBuilderDataProvider")
    public void testDoSLO(Object requestData) throws Exception {

        DefaultSAML2SSOManager.doBootstrap();

        mockXPathFactory();

        String samlRequest = buildSAMLRequest(true, (RequestData) requestData);
        when(mockedHttpServletRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn
                (samlRequest);

        DefaultSAML2SSOManager defaultSAML2SSOManager = new DefaultSAML2SSOManager();
        defaultSAML2SSOManager.doSLO(mockedHttpServletRequest);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private void assertAuthnRequest(AuthnRequest authnRequest, RequestData requestData) {

        if (StringUtils.isNotBlank(requestData.getSpEntityId())) {
            assertTrue(TestConstants.SP_ENTITY_ID.equals(authnRequest.getIssuer().getValue()), "Failed to set the " +
                    "issuer value");
        } else {
            assertTrue("carbonServer".equals(authnRequest.getIssuer().getValue()), "Failed to set the " +
                    "issuer value");
        }
        if (TestConstants.ACS_URL.equals(authnRequest.getAssertionConsumerServiceURL())) {
            assertTrue(TestConstants.ACS_URL.equals(authnRequest.getAssertionConsumerServiceURL()), "Failed to " +
                    "set the acs url");
        } else {
            assertTrue(TestConstants.IDP_ACS_URL.equals(authnRequest.getAssertionConsumerServiceURL()), "Failed" +
                    " to set the acs url");
        }
        assertTrue(TestConstants.IDP_URL.equals(authnRequest.getDestination()), "Failed to set the idp url.");
        if (StringUtils.isEmpty(requestData.getProtocolBinding()) || Boolean.parseBoolean(requestData.getProtocolBinding())) {
            assertTrue(SAMLConstants.SAML2_POST_BINDING_URI.equals(authnRequest.getProtocolBinding()), "Failed" +
                    " to set the request binding");
        } else {
            assertNull(authnRequest.getProtocolBinding(), "Invalid protocol binding configuration");
        }

        if ("yes".equals(requestData.getForceAuthenticateProp())) {
            assertTrue(authnRequest.isForceAuthn(), "Failed to set request as force authenticate request");
        } else if ("as_request".equals(requestData.getForceAuthenticateProp())) {
            if (mockedAuthenticationContext.isForceAuthenticate()) {
                assertTrue(authnRequest.isForceAuthn(), "Failed to set request as force authenticate request");
            }
        } else {
            assertFalse(authnRequest.isForceAuthn(), "Invalid force authentication request");
        }
        if (StringUtils.isNotBlank(requestData.getAcsIndex())) {
            assertTrue(TestConstants.ACS_INDEX.equals(authnRequest.getAttributeConsumingServiceIndex().toString()),
                    "Failed to set ACS index");
        }
        if (StringUtils.isEmpty(requestData.getIncludeNameIDPolicyProp()) || Boolean.parseBoolean(requestData
                .getIncludeNameIDPolicyProp())) {
            assertNotNull(authnRequest.getNameIDPolicy(), "Failed to set NameID policy");
        } else {
            assertNull(authnRequest.getNameIDPolicy(), "Invalid NameID policy");
        }
    }

    private void setParametersForBuildAuthnRequest(boolean isLogout, RequestData requestData, RequestData
            inboundRequestData, Map<String, String> authenticatorProperties) throws Exception {

        if (requestData.isSignRequest()) {
            addSignatureProperties(authenticatorProperties, requestData.isIncludeCertProperty());
        }

        String samlRequest = buildSAMLRequest(isLogout, inboundRequestData);


        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID,
                requestData.getSpEntityId());

        if ("yes".equals(requestData.getForceAuthenticateProp())) {
            authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION,
                    "yes");
        } else if ("as_request".equals(requestData.getForceAuthenticateProp())) {
            authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION,
                    "as_request");
            when(mockedAuthenticationContext.isForceAuthenticate()).thenReturn(true);
        }

        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING,
                requestData.getProtocolBinding());

        mockStatic(FileBasedConfigurationBuilder.class);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockedFileBasedConfigurationBuilder);

        Map<String, AuthenticatorConfig> authenticatorConfigMap = new HashMap<>();
        authenticatorConfigMap.put(SSOConstants.AUTHENTICATOR_NAME, mockedAuthenticatorConfig);
        when(mockedFileBasedConfigurationBuilder.getAuthenticatorConfigMap()).thenReturn(authenticatorConfigMap);
        if (requestData.isAuthenticatorConfigAvailable()) {
            when(mockedFileBasedConfigurationBuilder.getAuthenticatorBean(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(mockedAuthenticatorConfig);
            Map<String, String> parameterMap = new HashMap<>();
            parameterMap.put(SSOConstants.ServerConfig.SAML_SSO_ACS_URL, requestData.getAcsUrl());
            parameterMap.put("SignAuth2SAMLUsingSuperTenant", "true");
            when(mockedAuthenticatorConfig.getParameterMap()).thenReturn(parameterMap);
            if (StringUtils.isEmpty(authenticatorProperties.get(ACS_URL)) &&
                    StringUtils.isEmpty(requestData.getAcsUrl())) {
                when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true)).thenReturn(TestConstants
                        .ACS_URL);
            }
        } else {
            when(mockedFileBasedConfigurationBuilder.getAuthenticatorBean(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(null);
            when(IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true)).thenReturn(requestData
                    .getAcsUrl());
        }

        if (StringUtils.isNotBlank(requestData.getAcsIndex())) {
            authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO
                    .ATTRIBUTE_CONSUMING_SERVICE_INDEX, requestData.getAcsIndex());
        }

        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY,
                requestData.getIncludeNameIDPolicyProp());

        when(mockedAuthenticationContext.getAuthenticationRequest()).thenReturn(mockedAuthenticationRequest);
        when(mockedAuthenticationRequest.getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))
                .thenReturn(new String[]{samlRequest});
        if (SAMLConstants.SAML2_POST_BINDING_URI.equals(inboundRequestData.getHttpBinding())) {
            when(mockedAuthenticationRequest.isPost()).thenReturn(true);
        } else {
            when(mockedAuthenticationRequest.isPost()).thenReturn(false);
        }

        if (requestData.isIncludePostParam()) {
            when(mockedHttpServletRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn
                    (samlRequest);
        } else {
            when(mockedHttpServletRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn
                    (null);
            when(mockedAuthenticationContext.getQueryParams()).thenReturn(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ
                    + "=" + samlRequest);
        }

        when(mockedAuthenticationContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        mockKeyStore();

        mockDOMImplementationRegistry(mockedDomImplementationRegistry);
    }

    private String buildSAMLRequest(boolean isLogout, RequestData requestData) throws Exception {

        mockDocumentBuilderFactory();

        String samlRequest;
        if (!isLogout) {
            samlRequest = TestUtils.buildRequest(false, requestData);
        } else {
            samlRequest = TestUtils.buildRequest(true, requestData);
        }

        return samlRequest;
    }

    private void addSignatureProperties(Map<String, String> authenticatorProperties, boolean includeCert) {

        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED,
                Boolean.TRUE.toString());
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM,
                IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1);
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM,
                IdentityApplicationConstants.XML.DigestAlgorithm.SHA1);
        if (includeCert) {
            authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT,
                    Boolean.TRUE.toString());
        } else {
            authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT,
                    Boolean.FALSE.toString());
        }
    }

    private void mockKeyStore() throws Exception {

        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantManager()).thenReturn(mockedTenantManager);
        when(mockedTenantManager.getTenantId(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID);
        when(mockedTenantManager.getTenantId(TestConstants.SAMPLE_TENANT_DOMAIN_NAME))
                .thenReturn(TestConstants.SAMPLE_TENANT_ID);

        keyStore = SSOUtils.loadKeyStoreFromFileSystem(TestUtils.getFilePath("wso2carbon.jks"),
                TestConstants.KEY_STORE_PASSWORD, "JKS");
        key = keyStore.getKey(TestConstants.KEY_ALIAS, TestConstants.KEY_PASSWORD.toCharArray());
        certificate = keyStore.getCertificate(TestConstants.KEY_ALIAS);

        x509CredentialImpl = new X509CredentialImpl(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                TestConstants.IDP_CERTIFICATE);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID))
                .thenReturn(mockedSuperTenantKeyStoreManager);
        when(mockedSuperTenantKeyStoreManager.getDefaultPrivateKey()).thenReturn((PrivateKey) key);
        when(mockedSuperTenantKeyStoreManager.getDefaultPrimaryCertificate()).thenReturn((X509Certificate) certificate);
    }

    private String getDecodedSAMLRedirectRequest(String request) throws Exception {

        request = URLDecoder.decode(request, "UTF-8");
        String[] requestComponents = request.split("\\?");
        if (requestComponents.length == 2) {
            String[] requestParams = requestComponents[1].split("&");
            for (String param : requestParams) {
                if (param.contains(TestConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)) {
                    return SSOUtils.decode(param.split(TestConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ + "=")[1]);
                }
            }
        }
        return null;
    }

    public static String getDecodedSAMLPostRequest(String request) throws Exception {

        org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
        byte[] xmlBytes = request.getBytes("UTF-8");
        byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);
        return new String(base64DecodedByteArray, "UTF-8");
    }

    @Test
    public void validateSignatureExceptionTest() throws Exception {

        Class<?> clazz = DefaultSAML2SSOManager.class;
        Object defaultSAML2SSOManager = clazz.newInstance();
        Method validateSignature = defaultSAML2SSOManager.getClass().getDeclaredMethod("validateSignature",
                XMLObject.class);
        validateSignature.setAccessible(true);
        try {
            validateSignature.invoke(defaultSAML2SSOManager, mockedSignatureImpl);
            fail("IllegalAccessException or InvocationTargetException should have been thrown");
        } catch (IllegalAccessException | InvocationTargetException e) {
            assertTrue(true);
        }
    }

}
