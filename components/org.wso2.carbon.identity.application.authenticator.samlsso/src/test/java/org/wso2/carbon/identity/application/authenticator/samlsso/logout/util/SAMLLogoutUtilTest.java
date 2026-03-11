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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.util;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.security.SecurityException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.cert.RemoteCertificateProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLLogoutException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators.LogoutReqSignatureValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.IdentityException;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

public class SAMLLogoutUtilTest {

    private static final String ISSUER = "https://idp.example.com";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String QUERY_STRING = "SAMLRequest=test&SigAlg=RSA-SHA256&Signature=dGVzdA%3D%3D";
    private static final String IDP_NAME = "testIdP";
    private static final String MOCK_CERT_BASE64 = "dGVzdENlcnQ=";

    @Mock
    private LogoutRequest mockLogoutRequest;

    @Mock
    private Issuer mockIssuer;

    @Mock
    private SAMLLogoutRequest mockSAMLLogoutRequest;

    @Mock
    private IdentityProvider mockIdP;

    private AutoCloseable mocks;
    private SAMLMessageContext<String, String> samlMessageContext;

    @BeforeMethod
    public void setUp() {

        mocks = MockitoAnnotations.openMocks(this);
        samlMessageContext = new SAMLMessageContext<>(mockSAMLLogoutRequest, new HashMap<>());
        samlMessageContext.setTenantDomain(TENANT_DOMAIN);
        samlMessageContext.setFederatedIdP(mockIdP);

        when(mockLogoutRequest.getIssuer()).thenReturn(mockIssuer);
        when(mockIssuer.getValue()).thenReturn(ISSUER);
        when(mockIdP.getIdentityProviderName()).thenReturn(IDP_NAME);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mocks.close();
    }

    @Test(description = "When validateWithRemoteCertificates succeeds and returns true, "
            + "isValidSignature should return true without falling back to cert-based validation.")
    public void testIsValidSignature_RemoteCertValidation_ReturnsTrue() throws SAMLLogoutException {

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                LogoutReqSignatureValidator.class,
                (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                        mockLogoutRequest, samlMessageContext)).thenReturn(true))) {

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "When validateWithRemoteCertificates succeeds and returns false, "
            + "isValidSignature should return false without falling back to cert-based validation.")
    public void testIsValidSignature_RemoteCertValidation_ReturnsFalse() throws SAMLLogoutException {

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                LogoutReqSignatureValidator.class,
                (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                        mockLogoutRequest, samlMessageContext)).thenReturn(false))) {

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertFalse(result);
        }
    }

    @Test(description = "When no metadata URL is configured and the request uses POST binding, "
            + "isValidSignature should fall back to XML signature validation and return true.")
    public void testIsValidSignature_NoMetadataUrl_PostBinding_ValidXMLSignature() throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateXMLSignature(any(), any(), isNull())).thenReturn(true);
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class);
             MockedConstruction<X509CredentialImpl> credMock = mockConstruction(X509CredentialImpl.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "When no metadata URL is configured and the request uses POST binding, "
            + "isValidSignature should fall back to XML signature validation and return false.")
    public void testIsValidSignature_NoMetadataUrl_PostBinding_InvalidXMLSignature() throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateXMLSignature(any(), any(), isNull())).thenReturn(false);
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class);
             MockedConstruction<X509CredentialImpl> credMock = mockConstruction(X509CredentialImpl.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertFalse(result);
        }
    }

    @Test(description = "When no metadata URL is configured and the request uses redirect binding, "
            + "isValidSignature should fall back to query-string signature validation and return true.")
    public void testIsValidSignature_NoMetadataUrl_RedirectBinding_ValidQuerySignature() throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(QUERY_STRING);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateSignature(QUERY_STRING, ISSUER, mockX509Cert)).thenReturn(true);
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "When no metadata URL is configured and the request uses redirect binding, "
            + "isValidSignature should fall back to query-string signature validation and return false.")
    public void testIsValidSignature_NoMetadataUrl_RedirectBinding_InvalidQuerySignature() throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(QUERY_STRING);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateSignature(QUERY_STRING, ISSUER, mockX509Cert)).thenReturn(false);
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertFalse(result);
        }
    }

    @Test(description = "When remote cert validation fails with SIGNATURE_VALIDATION_FAILED and certs are "
            + "successfully refreshed, the retry should succeed and isValidSignature should return true.")
    public void testIsValidSignature_SignatureValidationFailed_CertsRefreshed_RetryReturnsTrue() throws Exception {

        SAMLSSOException sigValidationFailed = new SAMLSSOException(
                ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(), "Remote signature validation failed.");
        RemoteCertificateProcessor mockProcessor = mock(RemoteCertificateProcessor.class);

        when(mockProcessor.refreshCertificates(mockIdP, TENANT_DOMAIN)).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                             mockLogoutRequest, samlMessageContext))
                             .thenThrow(sigValidationFailed)
                             .thenReturn(true));
             MockedStatic<RemoteCertificateProcessor> processorMock = mockStatic(RemoteCertificateProcessor.class)) {

            processorMock.when(RemoteCertificateProcessor::getInstance).thenReturn(mockProcessor);

            boolean result = SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);

            assertTrue(result);
        }
    }

    @Test(description = "When remote cert validation fails with SIGNATURE_VALIDATION_FAILED and certs cannot be "
            + "refreshed (refreshCertificates returns false), isValidSignature should throw SAMLLogoutException.")
    public void testIsValidSignature_SignatureValidationFailed_CertsNotRefreshed_ThrowsSAMLLogoutException()
            throws Exception {

        SAMLSSOException sigValidationFailed = new SAMLSSOException(
                ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(), "Remote signature validation failed.");
        RemoteCertificateProcessor mockProcessor = mock(RemoteCertificateProcessor.class);

        when(mockProcessor.refreshCertificates(mockIdP, TENANT_DOMAIN)).thenReturn(false);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                             mockLogoutRequest, samlMessageContext))
                             .thenThrow(sigValidationFailed));
             MockedStatic<RemoteCertificateProcessor> processorMock = mockStatic(RemoteCertificateProcessor.class)) {

            processorMock.when(RemoteCertificateProcessor::getInstance).thenReturn(mockProcessor);

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }

    @Test(description = "When remote cert validation fails with SIGNATURE_VALIDATION_FAILED, certs are refreshed, "
            + "but the retry also throws an exception, isValidSignature should throw SAMLLogoutException.")
    public void testIsValidSignature_SignatureValidationFailed_CertsRefreshed_RetryThrows_ThrowsSAMLLogoutException()
            throws Exception {

        SAMLSSOException sigValidationFailed = new SAMLSSOException(
                ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(), "Remote signature validation failed.");
        SAMLSSOException retryException = new SAMLSSOException("Retry also failed.");
        RemoteCertificateProcessor mockProcessor = mock(RemoteCertificateProcessor.class);

        when(mockProcessor.refreshCertificates(mockIdP, TENANT_DOMAIN)).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                             mockLogoutRequest, samlMessageContext))
                             .thenThrow(sigValidationFailed)
                             .thenThrow(retryException));
             MockedStatic<RemoteCertificateProcessor> processorMock = mockStatic(RemoteCertificateProcessor.class)) {

            processorMock.when(RemoteCertificateProcessor::getInstance).thenReturn(mockProcessor);

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }

    @Test(description = "When validateWithRemoteCertificates throws a SAMLSSOException with an unrecognised error "
            + "code, isValidSignature should propagate it as a SAMLLogoutException.")
    public void testIsValidSignature_UnrecognisedSAMLSSOException_ThrowsSAMLLogoutException() {

        SAMLSSOException unexpectedException = new SAMLSSOException("SAM-99999", "Unknown remote error.");

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                LogoutReqSignatureValidator.class,
                (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                        mockLogoutRequest, samlMessageContext)).thenThrow(unexpectedException))) {

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }

    @Test(description = "When falling back to cert-based XML signature validation (POST) and validateXMLSignature "
            + "throws IdentityException, isValidSignature should throw SAMLLogoutException.")
    public void testIsValidSignature_FallbackPostBinding_IdentityException_ThrowsSAMLLogoutException()
            throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateXMLSignature(any(), any(), isNull()))
                                 .thenThrow(IdentityException.error("Invalid XML signature."));
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class);
             MockedConstruction<X509CredentialImpl> credMock = mockConstruction(X509CredentialImpl.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }

    @Test(description = "When falling back to cert-based query-string signature validation (redirect) and "
            + "validateSignature throws SecurityException, isValidSignature should throw SAMLLogoutException.")
    public void testIsValidSignature_FallbackRedirectBinding_SecurityException_ThrowsSAMLLogoutException()
            throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");
        X509Certificate mockX509Cert = mock(X509Certificate.class);

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(false);
        when(mockSAMLLogoutRequest.getQueryString()).thenReturn(QUERY_STRING);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> {
                         when(validator.validateWithRemoteCertificates(mockLogoutRequest, samlMessageContext))
                                 .thenThrow(noMetadataException);
                         when(validator.validateSignature(any(), any(), any()))
                                 .thenThrow(new SecurityException("Security failure."));
                     });
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any())).thenReturn(mockX509Cert);

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }

    @Test(description = "When the IdP certificate string cannot be decoded into a valid X.509 certificate, "
            + "isValidSignature should throw SAMLLogoutException.")
    public void testIsValidSignature_InvalidIdPCertificate_ThrowsSAMLLogoutException() throws Exception {

        SAMLSSOException noMetadataException = new SAMLSSOException(
                ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(), "No metadata URL configured.");

        when(mockIdP.getCertificate()).thenReturn(MOCK_CERT_BASE64);
        when(mockSAMLLogoutRequest.isPost()).thenReturn(true);

        try (MockedConstruction<LogoutReqSignatureValidator> validatorMock = mockConstruction(
                     LogoutReqSignatureValidator.class,
                     (validator, ctx) -> when(validator.validateWithRemoteCertificates(
                             mockLogoutRequest, samlMessageContext)).thenThrow(noMetadataException));
             MockedStatic<CertificateFactory> cfMock = mockStatic(CertificateFactory.class)) {

            CertificateFactory mockCertFactory = mock(CertificateFactory.class);
            cfMock.when(() -> CertificateFactory.getInstance("X.509")).thenReturn(mockCertFactory);
            when(mockCertFactory.generateCertificate(any()))
                    .thenThrow(new CertificateException("Malformed certificate data."));

            try {
                SAMLLogoutUtil.isValidSignature(mockLogoutRequest, samlMessageContext);
                fail("Expected SAMLLogoutException was not thrown.");
            } catch (SAMLLogoutException e) {
                // expected
            }
        }
    }
}
