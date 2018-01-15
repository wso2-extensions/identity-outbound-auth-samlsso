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
package org.wso2.carbon.identity.application.authenticator.samlsso.util;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.util.HashMap;
import java.util.Map;

/**
 * Unit test cases for SSOUtils
 */
public class SSOUtilsTest {

    @Test
    public void testCreateID() {

        Assert.assertNotNull(SSOUtils.createID(), "Failed to generate an ID");
    }

    @Test
    public void testEncode() {

        Assert.assertEquals(SSOUtils.encode(TestConstants.XML_STRING), TestConstants.ENCODED_STRING, "Failed to " +
                "encode the xml");
    }

    @Test
    public void testDecode() throws SAMLSSOException {

        Assert.assertEquals(SSOUtils.decode(TestConstants.REDIRECT_REQUEST), TestConstants.REDIRECT_DECODED_STRING,
                "Failed to decode the redirect binding message");
    }

    @Test(expectedExceptions = RuntimeException.class)
    public void testDecodeEmptyRequest() throws SAMLSSOException {

        String emptyRedirectRequest = "";
        SSOUtils.decode(emptyRedirectRequest);
    }

    @Test(expectedExceptions = {SAMLSSOException.class})
    public void testDecodeForInvalidRequest() throws SAMLSSOException {

        SSOUtils.decode(TestConstants.INVALID_REDIRECT_REQUEST);
    }

    @Test
    public void testDecodeForPost() throws SAMLSSOException {

        Assert.assertEquals(SSOUtils.decodeForPost(TestConstants.POST_REQUEST), TestConstants.POST_DECODED_STRING,
                "Failed to decode post binding message");
    }

    @Test
    public void testIsAuthnRequestSigned() {

        Assert.assertFalse(SSOUtils.isAuthnRequestSigned(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isAuthnRequestSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED, "false");
        Assert.assertFalse(SSOUtils.isAuthnRequestSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED, "true");
        Assert.assertTrue(SSOUtils.isAuthnRequestSigned(properties), "Failed to read a valid property");
    }

    @Test
    public void testIsLogoutEnabled() {

        Assert.assertFalse(SSOUtils.isLogoutEnabled(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isLogoutEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED, "false");
        Assert.assertFalse(SSOUtils.isLogoutEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED, "true");
        Assert.assertTrue(SSOUtils.isLogoutEnabled(properties), "Failed to read a valid property");
    }

    @Test
    public void testIsLogoutRequestSigned() {

        Assert.assertFalse(SSOUtils.isLogoutRequestSigned(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isLogoutRequestSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED, "false");
        Assert.assertFalse(SSOUtils.isLogoutRequestSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED, "true");
        Assert.assertTrue(SSOUtils.isLogoutRequestSigned(properties), "Failed to read a valid property");
    }

    @Test
    public void testIsAuthnResponseSigned() {

        Assert.assertFalse(SSOUtils.isAuthnResponseSigned(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isAuthnResponseSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED, "false");
        Assert.assertFalse(SSOUtils.isAuthnResponseSigned(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED, "true");
        Assert.assertTrue(SSOUtils.isAuthnResponseSigned(properties), "Failed to read a valid property");
    }

    @Test
    public void testIsAssertionSigningEnabled() {

        Assert.assertFalse(SSOUtils.isAssertionSigningEnabled(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isAssertionSigningEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_SIGNING, "false");
        Assert.assertFalse(SSOUtils.isAssertionSigningEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_SIGNING, "true");
        Assert.assertTrue(SSOUtils.isAssertionSigningEnabled(properties), "Failed to read a valid property");
    }

    @Test
    public void testIsAssertionEncryptionEnabled() {

        Assert.assertFalse(SSOUtils.isAssertionEncryptionEnabled(null), "Returned true for an invalid input");

        Map<String, String> properties = new HashMap<>();
        Assert.assertFalse(SSOUtils.isAssertionEncryptionEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_ENCRYPTION, "false");
        Assert.assertFalse(SSOUtils.isAssertionEncryptionEnabled(properties), "Returned true for an invalid input");

        properties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_ENCRYPTION, "true");
        Assert.assertTrue(SSOUtils.isAssertionEncryptionEnabled(properties), "Failed to read a valid property");
    }

    @Test
    public void testGetQueryMap() {

        Assert.assertTrue(SSOUtils.getQueryMap("").isEmpty());

        Map<String, String> queryParams = SSOUtils.getQueryMap(TestConstants.QUERY_STRING);

        Assert.assertTrue(!queryParams.isEmpty(), "Failed to extract the query params");
        Assert.assertEquals(queryParams.get("SAMLRequest"), TestConstants.SAML_REQUEST_PARAMETER, "Failed to extract " +
                "the SAMLRequest query param");
        Assert.assertEquals(queryParams.get("SigAlg"), TestConstants.SIG_ALG_PARAMETER, "Failed to extract the " +
                "SigAlg query param");
        Assert.assertEquals(queryParams.get("Signature"), TestConstants.SIGNATURE_PARAMETER, "Failed to extract the " +
                "Signature query param");
        Assert.assertEquals(queryParams.get("empty"), "", "Failed to extract the empty query param");
    }
}
