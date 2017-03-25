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
import java.util.Properties;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

/**
 * SAML outbound post binding tests.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLOutboundCommonTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLOutboundPOSTTests.class);

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
     * SAML outbound federated authentication with post binding
     */
    @Test
    public void testMinimumConfigs() {

        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        Properties originalProperties = identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                ().get(0).getProperties();

        try {
            Properties newProperties = new Properties();
            newProperties.setProperty(SAML2AuthConstants.Config.Name.SAML2_SSO_URL, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.SAML2_SSO_URL));

            newProperties.setProperty(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.SP_ENTITY_ID));

            newProperties.setProperty(SAML2AuthConstants.Config.Name.IDP_ENTITY_ID, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.IDP_ENTITY_ID));

            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(newProperties);

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT + "?" +
                    SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET, false);
            String content = SAMLOutboundTestUtils.getContent(urlConnection);
            String relayState = SAMLOutboundTestUtils.getParameterFromHTML(content, "'RelayState' value='", "'>");
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
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(originalProperties);
        }
    }

    @Test
    public void testWithResponseSigningAndAssertionEncryption() {

        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        Properties originalProperties = identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                ().get(0).getProperties();

        try {
            Properties newProperties = new Properties();
            newProperties.setProperty(SAML2AuthConstants.Config.Name.SAML2_SSO_URL, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.SAML2_SSO_URL));

            newProperties.setProperty(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.SP_ENTITY_ID));
            newProperties.setProperty(SAML2AuthConstants.Config.Name.IDP_ENTITY_ID, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.IDP_ENTITY_ID));
            newProperties.setProperty(SAML2AuthConstants.Config.Name.AUTHN_RESPONSE_SIGNED, "true");
            newProperties.setProperty(SAML2AuthConstants.Config.Name.AUTHN_RESPONSE_ENCRYPTED, "true");
            newProperties.setProperty(SAML2AuthConstants.Config.Name.DIGEST_ALGO, "http://www.w3" +
                    ".org/2001/04/xmldsig-more#md5");
            newProperties.setProperty(SAML2AuthConstants.Config.Name.SIGNATURE_ALGO, "http://www.w3" +
                    ".org/2000/09/xmldsig#dsa-sha1");

            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(newProperties);

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT + "?" +
                    SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET, false);
            String content = SAMLOutboundTestUtils.getContent(urlConnection);
            String relayState = SAMLOutboundTestUtils.getParameterFromHTML(content, "'RelayState' value='", "'>");
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse(true, SAMLOutboundTestConstants
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
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(originalProperties);
        }
    }


    @Test
    public void testRequestSigning() {

        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        Properties originalProperties = identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                ().get(0).getProperties();

        try {
            Properties newProperties = new Properties();
            newProperties.setProperty(SAML2AuthConstants.Config.Name.SAML2_SSO_URL, originalProperties.getProperty
                    (SAML2AuthConstants.Config.Name.SAML2_SSO_URL));

            newProperties.setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");


            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(newProperties);

            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT + "?" +
                    SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET, false);
            String content = SAMLOutboundTestUtils.getContent(urlConnection);
            String relayState = SAMLOutboundTestUtils.getParameterFromHTML(content, "'RelayState' value='", "'>");
            String samlRequest = SAMLOutboundTestUtils.getParameterFromHTML(content, "'SAMLRequest' value='","'>" );

            String decodedRequest = SAML2AuthUtils.decodeForPost(samlRequest);
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            Assert.assertTrue(request instanceof AuthnRequest);
            AuthnRequest authnRequest = (AuthnRequest) request;
            Assert.assertNotNull(authnRequest.getSignature());
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs
                    ().get(0).setProperties(originalProperties);
        }
    }

}
