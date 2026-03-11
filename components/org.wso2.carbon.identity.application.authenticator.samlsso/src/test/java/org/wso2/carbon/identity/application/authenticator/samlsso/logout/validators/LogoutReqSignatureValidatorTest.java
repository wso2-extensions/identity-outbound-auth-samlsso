/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.xmlsec.signature.Signature;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.cert.RemoteCertificateProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class LogoutReqSignatureValidatorTest {

    private static final String VALID_QUERY_STRING =
            "SAMLRequest=testRequest&SigAlg=RSA-SHA256&Signature=dGVzdA%3D%3D";

    private static final String QUERY_STRING_MISSING_SIGNATURE =
            "SAMLRequest=testRequest&SigAlg=RSA-SHA256";

    private static final String QUERY_STRING_MISSING_SIGALG =
            "SAMLRequest=testRequest&Signature=dGVzdA%3D%3D";

    private static final String ISSUER = "https://idp.example.com";
    private static final String TENANT_DOMAIN = "carbon.super";

    @Mock
    private LogoutRequest mockLogoutRequest;

    @Mock
    private Issuer mockIssuer;

    @Mock
    private SAMLLogoutRequest mockSAMLLogoutRequest;

    @Mock
    private IdentityProvider mockIdP;

    @Mock
    private Signature mockSignature;

    private AutoCloseable mocks;
    private SAMLMessageContext<String, String> samlMessageContext;
    private LogoutReqSignatureValidator validator;

    @BeforeMethod
    public void setUp() {

        mocks = MockitoAnnotations.openMocks(this);

        samlMessageContext = new SAMLMessageContext<>(mockSAMLLogoutRequest, new HashMap<>());
        samlMessageContext.setTenantDomain(TENANT_DOMAIN);
        samlMessageContext.setFederatedIdP(mockIdP);

        when(mockLogoutRequest.getIssuer()).thenReturn(mockIssuer);
        when(mockIssuer.getValue()).thenReturn(ISSUER);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(VALID_QUERY_STRING);

        validator = new LogoutReqSignatureValidator();
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mocks.close();
    }

    @Test(description = "POST binding: when the logout request has no XML signature element, "
            + "validateWithRemoteCertificates should return false without invoking RemoteCertificateProcessor.")
    public void testValidateWithRemoteCertificates_PostBinding_NullSignature_ReturnsFalse()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);
        when(mockLogoutRequest.getSignature()).thenReturn(null);

        boolean result = validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);

        assertFalse(result);
    }

    @Test(description = "POST binding: when the logout request has a valid XML signature element and "
            + "RemoteCertificateProcessor.validateSignature completes without error, "
            + "validateWithRemoteCertificates should return true.")
    public void testValidateWithRemoteCertificates_PostBinding_ValidSignature_ReturnsTrue()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);
        when(mockLogoutRequest.getSignature()).thenReturn(mockSignature);

        RemoteCertificateProcessor mockRCP = mock(RemoteCertificateProcessor.class);
        doNothing().when(mockRCP).validateSignature(any(), any(), any());

        try (MockedStatic<RemoteCertificateProcessor> rcpStatic =
                     mockStatic(RemoteCertificateProcessor.class)) {
            rcpStatic.when(RemoteCertificateProcessor::getInstance).thenReturn(mockRCP);

            boolean result = validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "POST binding: when RemoteCertificateProcessor.validateSignature throws a "
            + "SAMLSSOException (e.g. metadata URL not configured, bad certificate), "
            + "validateWithRemoteCertificates should propagate that exception.")
    public void testValidateWithRemoteCertificates_PostBinding_ValidateSignatureThrows_PropagatesSAMLSSOException()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);
        when(mockLogoutRequest.getSignature()).thenReturn(mockSignature);

        RemoteCertificateProcessor mockRCP = mock(RemoteCertificateProcessor.class);
        doThrow(new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                "No metadata URL configured for IdP."))
                .when(mockRCP).validateSignature(any(), any(), any());

        try (MockedStatic<RemoteCertificateProcessor> rcpStatic =
                     mockStatic(RemoteCertificateProcessor.class)) {
            rcpStatic.when(RemoteCertificateProcessor::getInstance).thenReturn(mockRCP);

            try {
                validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLSSOException to be thrown");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(), ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode());
            }
        }
    }

    @Test(description = "Redirect binding: when the query string is valid and "
            + "RemoteCertificateProcessor.validateQueryStringSignature returns true, "
            + "validateWithRemoteCertificates should return true.")
    public void testValidateWithRemoteCertificates_RedirectBinding_ValidSignature_ReturnsTrue()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);

        RemoteCertificateProcessor mockRCP = mock(RemoteCertificateProcessor.class);
        when(mockRCP.validateQueryStringSignature(any(), any(), any(), any(), any(), any()))
                .thenReturn(true);

        try (MockedStatic<RemoteCertificateProcessor> rcpStatic =
                     mockStatic(RemoteCertificateProcessor.class)) {
            rcpStatic.when(RemoteCertificateProcessor::getInstance).thenReturn(mockRCP);

            boolean result = validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "Redirect binding: when the query string is valid and "
            + "RemoteCertificateProcessor.validateQueryStringSignature returns false, "
            + "validateWithRemoteCertificates should return false.")
    public void testValidateWithRemoteCertificates_RedirectBinding_InvalidSignature_ReturnsFalse()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);

        RemoteCertificateProcessor mockRCP = mock(RemoteCertificateProcessor.class);
        when(mockRCP.validateQueryStringSignature(any(), any(), any(), any(), any(), any()))
                .thenReturn(false);

        try (MockedStatic<RemoteCertificateProcessor> rcpStatic =
                     mockStatic(RemoteCertificateProcessor.class)) {
            rcpStatic.when(RemoteCertificateProcessor::getInstance).thenReturn(mockRCP);

            boolean result = validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);

            assertFalse(result);
        }
    }

    @Test(description = "Redirect binding: when the query string is missing the 'Signature' parameter, "
            + "getSignature() throws a SecurityException that is caught and re-thrown as a SAMLSSOException "
            + "with error code LOGOUT_REQUEST_QUERY_STRING_PARSING_FAILED.")
    public void testValidateWithRemoteCertificates_RedirectBinding_MissingSignatureParam_ThrowsSAMLSSOException() {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(QUERY_STRING_MISSING_SIGNATURE);

        try {
            validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);
            fail("Expected SAMLSSOException to be thrown");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.LOGOUT_REQUEST_QUERY_STRING_PARSING_FAILED.getCode());
        }
    }

    @Test(description = "Redirect binding: when the query string is missing the 'SigAlg' parameter, "
            + "getSignatureAlgorithm() throws a SecurityException that is caught and re-thrown as a "
            + "SAMLSSOException with error code LOGOUT_REQUEST_QUERY_STRING_PARSING_FAILED.")
    public void testValidateWithRemoteCertificates_RedirectBinding_MissingSigAlgParam_ThrowsSAMLSSOException() {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(QUERY_STRING_MISSING_SIGALG);

        try {
            validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);
            fail("Expected SAMLSSOException to be thrown");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.LOGOUT_REQUEST_QUERY_STRING_PARSING_FAILED.getCode());
        }
    }

    @Test(description = "Redirect binding: when RemoteCertificateProcessor.validateQueryStringSignature "
            + "throws a SAMLSSOException (e.g. metadata URL not configured), the exception is NOT caught "
            + "by the SecurityException/IdentityException handler and propagates directly.")
    public void testValidateWithRemoteCertificates_RedirectBinding_ValidateQueryStringThrows_PropagatesSAMLSSOException()
            throws SAMLSSOException {

        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);

        RemoteCertificateProcessor mockRCP = mock(RemoteCertificateProcessor.class);
        when(mockRCP.validateQueryStringSignature(any(), any(), any(), any(), any(), any()))
                .thenThrow(new SAMLSSOException(
                        ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                        "No metadata URL configured for IdP."));

        try (MockedStatic<RemoteCertificateProcessor> rcpStatic =
                     mockStatic(RemoteCertificateProcessor.class)) {
            rcpStatic.when(RemoteCertificateProcessor::getInstance).thenReturn(mockRCP);

            try {
                validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLSSOException to be thrown");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode());
            }
        }
    }
}
