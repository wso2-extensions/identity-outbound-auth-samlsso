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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.test;

import com.google.common.net.HttpHeaders;
import org.apache.commons.io.Charsets;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.CoreOptions;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.common.model.idp.IdentityProviderConfig;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

/**
 * Tests the TestService.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLOutboundRedirectTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLOutboundRedirectTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SAMLOutboundOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(SAMLOutboundOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    /**
     * Test SAML outbound authentication with redirect binding.
     */
    @Test
    public void testSAMLFederatedAuthenticationWithRedirectBinding() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);
        try {
            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                            .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET,
                    false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, SAMLOutboundTestConstants
                    .CARBON_SERVER, true, true);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains("authenticatedUser=" + SAMLOutboundTestConstants
                    .AUTHENTICATED_USER_NAME));
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                            .POST);
        }
    }


    /**
     * Assert the content of outbound authentication request with redirect binding.
     */
    @Test
    public void assertRequestContentWithRedirectBinding() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);
        try {
            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                            .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET,
                    false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;
            Assert.assertNotNull(authnRequest);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, SAMLOutboundTestConstants
                    .CARBON_SERVER, true, true);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains("authenticatedUser=" + SAMLOutboundTestConstants
                    .AUTHENTICATED_USER_NAME));
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                            .POST);
        }
    }

    /**
     * Assert the content of outbound authentication request with redirect binding.
     */
    @Test
    public void assertIssuerWithRedirectBinding() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);

        String externalIDPName = "externalIDPName";
        String originalBinding = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs()
                .get(0).getProperties().get(SAML2AuthConstants.Config.Name.REQUEST_BINDING);
        String originalSPEntityId = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                ().get(0).getProperties().get(SAML2AuthConstants.Config.Name.SP_ENTITY_ID);

        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);
        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, externalIDPName);
        try {

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                    .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod
                    .GET, false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;

            Assert.assertEquals(authnRequest.getIssuer().getValue(), externalIDPName);
            Assert.assertNotNull(authnRequest);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, externalIDPName, true, true);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains("authenticatedUser=" + SAMLOutboundTestConstants
                    .AUTHENTICATED_USER_NAME));

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, originalBinding);
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, originalSPEntityId);
        }
    }


    /**
     * Assert the content of outbound authentication request with redirect binding.
     */
    @Test
    public void testNonExistingIssuer() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);

        String originalBinding = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs()
                .get(0).getProperties().get(SAML2AuthConstants.Config.Name.REQUEST_BINDING);
        String originalSPEntityId = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                ().get(0).getProperties().get(SAML2AuthConstants.Config.Name.SP_ENTITY_ID);

        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);
        try {

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                    .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod
                    .GET, false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;
            Assert.assertNotNull(authnRequest);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, SAMLOutboundTestConstants
                    .CARBON_SERVER + "nonExisting", true, true);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            Assert.assertEquals(urlConnection.getResponseCode(), 500);

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, originalBinding);
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, originalSPEntityId);
        }
    }


    /**
     * Assert the content of outbound authentication request with redirect binding.
     */
    @Test
    public void testResponseWithoutSignature() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);

        String originalBinding = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs()
                .get(0).getProperties().get(SAML2AuthConstants.Config.Name.REQUEST_BINDING);

        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);

        try {

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                    .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod
                    .GET, false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;

            Assert.assertNotNull(authnRequest);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, SAMLOutboundTestConstants
                    .CARBON_SERVER, false, true);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains("authenticatedUser=" + SAMLOutboundTestConstants
                    .AUTHENTICATED_USER_NAME));

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, originalBinding);
        }
    }


    /**
     * Assert the content of outbound authentication request with redirect binding.
     */
    @Test
    public void testResponseWithoutAssertionSigning() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);

        String originalBinding = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs()
                .get(0).getProperties().get(SAML2AuthConstants.Config.Name.REQUEST_BINDING);

        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);

        try {

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
                    .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod
                    .GET, false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;

            Assert.assertNotNull(authnRequest);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(false, SAMLOutboundTestConstants
                    .CARBON_SERVER, true, false);
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertEquals(500, urlConnection.getResponseCode());
            Assert.assertNull(locationHeader);

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, originalBinding);
        }
    }


//    /**
//     * Assert the content of outbound authentication request with redirect binding.
//     */
//    @Test
//    public void testEncryptedAssertions() {
//        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
//                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
//
//        String originalBinding = (String) identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs()
//                .get(0).getProperties().get(SAML2AuthConstants.Config.Name.REQUEST_BINDING);
//
//        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
//                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
//                        .REDIRECT);
//
//        try {
//
//            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants
//                    .GATEWAY_ENDPOINT + "?" + SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod
//                    .GET, false);
//            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
//            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
//                    (location);
//            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
//            String federatedSAMLRequest = queryParams.get(SAML2AuthConstants.SAML_REQUEST);
//            String decodedRequest = SAML2AuthUtils.decodeForRedirect(federatedSAMLRequest);
//            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
//            AuthnRequest authnRequest = (AuthnRequest) request;
//
//            Assert.assertNotNull(authnRequest);
//            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(true, SAMLOutboundTestConstants
//                    .CARBON_SERVER, true, true);
//            samlResponse = URLEncoder.encode(samlResponse);
//            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
//                    true);
//            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
//            urlConnection.setDoOutput(true);
//            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
//            urlConnection.getResponseCode();
//            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
//            Assert.assertEquals(500, urlConnection.getResponseCode());
//            Assert.assertNull(locationHeader);
//
//        } catch (IOException e) {
//            Assert.fail("Error while running federated authentication test case");
//        } catch (IdentityException e) {
//            Assert.fail("Error while running federated authentication test case");
//        } finally {
//            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
//                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, originalBinding);
//        }
//    }
}
