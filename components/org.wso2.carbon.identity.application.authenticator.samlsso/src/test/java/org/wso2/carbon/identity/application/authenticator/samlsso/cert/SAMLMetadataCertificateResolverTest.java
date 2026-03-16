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

package org.wso2.carbon.identity.application.authenticator.samlsso.cert;

import org.mockito.MockedStatic;
import org.opensaml.core.xml.XMLObject;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.RemoteCertificate;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.external.api.client.api.exception.APIClientException;
import org.wso2.carbon.identity.external.api.client.api.model.APIResponse;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

public class SAMLMetadataCertificateResolverTest {

    private static final String TEST_PARAM = "TestParam";
    private static final int INT_DEFAULT = 100;
    private static final long LONG_DEFAULT = 200L;
    private static final String RAW_METADATA = "<EntityDescriptor/>"; // content irrelevant; SSOUtils.unmarshall is mocked
    private static final String METADATA_URL = "https://idp.example.com/saml/metadata";
    private static final String ENTITY_ID = "https://idp.example.com";

    private static final String VALID_BASE64_DER =
            "MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls"
          + "b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD"
          + "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7"
          + "o4qne60TB3pSPxuEbCcCnFf+8lbBKFGHpVfhHjvwOHDDjckkGLImFynzFcBYFix5"
          + "pLXCMJSHFBBMmBVr7GZhKJp0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
          + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDAQABo1MwUTAdBgNVHQ4EFgQU"
          + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0wHwYDVR0jBBgwFoAUAAAAAAAAAAAAAAAA"
          + "AAAAAAAAAAAAAAAAA0wDQYJKoZIhvcNAQELBQADggEBAAAAAAAAAAAAAAAAAAAAAA==";

    @BeforeClass
    public void setUpClass() {

        System.setProperty("carbon.home", getClass().getResource("/").getPath());
        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            SAMLMetadataCertificateResolver.getInstance();
        }
    }

    @Test(description = "When the param key is absent from the config map, "
            + "getClientIntParam should return the supplied default value.")
    public void testGetClientIntParam_ParamAbsent_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.emptyMap());

            int result = invokeGetClientIntParam(TEST_PARAM, INT_DEFAULT);

            assertEquals(result, INT_DEFAULT, "Should return default when param is absent.");
        }
    }

    @Test(description = "When the param value is blank whitespace, "
            + "getClientIntParam should return the supplied default value.")
    public void testGetClientIntParam_ParamBlank_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "   "));

            int result = invokeGetClientIntParam(TEST_PARAM, INT_DEFAULT);

            assertEquals(result, INT_DEFAULT, "Should return default when param value is blank.");
        }
    }

    @Test(description = "When the param value is a valid integer string, "
            + "getClientIntParam should return the parsed integer.")
    public void testGetClientIntParam_ValidInt_ReturnsParsedValue() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "5000"));

            int result = invokeGetClientIntParam(TEST_PARAM, INT_DEFAULT);

            assertEquals(result, 5000, "Should return parsed integer value.");
        }
    }

    @Test(description = "When the param value has surrounding whitespace, "
            + "getClientIntParam should trim it and return the parsed integer.")
    public void testGetClientIntParam_ValWithWhitespace_ReturnsTrimmedParsedValue() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "  99  "));

            int result = invokeGetClientIntParam(TEST_PARAM, INT_DEFAULT);

            assertEquals(result, 99, "Should trim whitespace and return parsed value.");
        }
    }

    @Test(description = "When the param value is a non-numeric string, getClientIntParam should "
            + "log an error and return the supplied default value.")
    public void testGetClientIntParam_NonNumericValue_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "notAnInt"));

            int result = invokeGetClientIntParam(TEST_PARAM, INT_DEFAULT);

            assertEquals(result, INT_DEFAULT, "Should return default when value cannot be parsed as int.");
        }
    }

    @Test(description = "When the param key is absent from the config map, "
            + "getClientLongParam should return the supplied default value.")
    public void testGetClientLongParam_ParamAbsent_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.emptyMap());

            long result = invokeGetClientLongParam(TEST_PARAM, LONG_DEFAULT);

            assertEquals(result, LONG_DEFAULT, "Should return default when param is absent.");
        }
    }

    @Test(description = "When the param value is blank whitespace, "
            + "getClientLongParam should return the supplied default value.")
    public void testGetClientLongParam_ParamBlank_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "   "));

            long result = invokeGetClientLongParam(TEST_PARAM, LONG_DEFAULT);

            assertEquals(result, LONG_DEFAULT, "Should return default when param value is blank.");
        }
    }

    @Test(description = "When the param value is a valid long string, "
            + "getClientLongParam should return the parsed long.")
    public void testGetClientLongParam_ValidLong_ReturnsParsedValue() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "524288000"));

            long result = invokeGetClientLongParam(TEST_PARAM, LONG_DEFAULT);

            assertEquals(result, 524288000L, "Should return parsed long value.");
        }
    }

    @Test(description = "When the param value has surrounding whitespace, "
            + "getClientLongParam should trim it and return the parsed long.")
    public void testGetClientLongParam_ValWithWhitespace_ReturnsTrimmedParsedValue() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "  512000  "));

            long result = invokeGetClientLongParam(TEST_PARAM, LONG_DEFAULT);

            assertEquals(result, 512000L, "Should trim whitespace and return parsed value.");
        }
    }

    @Test(description = "When the param value is a non-numeric string, getClientLongParam should "
            + "log an error and return the supplied default value.")
    public void testGetClientLongParam_NonNumericValue_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(Collections.singletonMap(TEST_PARAM, "notALong"));

            long result = invokeGetClientLongParam(TEST_PARAM, LONG_DEFAULT);

            assertEquals(result, LONG_DEFAULT, "Should return default when value cannot be parsed as long.");
        }
    }

    /**
     * Invokes the private static getClientIntParam method via reflection.
     */
    private int invokeGetClientIntParam(String paramName, int defaultValue) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("getClientIntParam", String.class, int.class);
        method.setAccessible(true);
        return (int) method.invoke(null, paramName, defaultValue);
    }

    /**
     * Invokes the private static getClientLongParam method via reflection.
     */
    private long invokeGetClientLongParam(String paramName, long defaultValue) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("getClientLongParam", String.class, long.class);
        method.setAccessible(true);
        return (long) method.invoke(null, paramName, defaultValue);
    }

    @Test(description = "When IdentityApplicationManagementUtil.decodeCertificate returns an X509Certificate, "
            + "decodeCertificate should return that same certificate.")
    public void testDecodeCertificate_ValidBase64_ReturnsCertificate() throws Exception {

        X509Certificate mockCert = mock(X509Certificate.class);

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(VALID_BASE64_DER))
                    .thenReturn(mockCert);

            X509Certificate result = invokeDecodeCertificate(VALID_BASE64_DER);

            assertSame(result, mockCert, "Should return the certificate returned by the utility.");
        }
    }

    @Test(description = "When the raw input contains embedded whitespace and newlines, "
            + "decodeCertificate should strip all whitespace before delegating to the utility.")
    public void testDecodeCertificate_InputWithWhitespace_WhitespaceStrippedBeforeDecoding() throws Exception {

        String inputWithWhitespace = "  MIIC pDCC\nAYwCC\tQDU  ";
        String expectedCleaned    = "MIICpDCCAYwCCQDU";
        X509Certificate mockCert  = mock(X509Certificate.class);

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(expectedCleaned))
                    .thenReturn(mockCert);

            X509Certificate result = invokeDecodeCertificate(inputWithWhitespace);

            assertSame(result, mockCert, "Should pass the whitespace-stripped value to the utility.");
        }
    }

    @Test(description = "When IdentityApplicationManagementUtil.decodeCertificate throws a CertificateException, "
            + "decodeCertificate should wrap it in a SAMLSSOException with error code SAM-65147.")
    public void testDecodeCertificate_CertificateException_ThrowsSAMLSSOException() throws Exception {

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenThrow(new CertificateException("bad cert"));

            try {
                invokeDecodeCertificate(VALID_BASE64_DER);
                throw new AssertionError("Expected SAMLSSOException was not thrown.");
            } catch (InvocationTargetException ite) {
                Throwable cause = ite.getCause();
                assertNotNull(cause, "InvocationTargetException must have a cause.");
                assertEquals(cause.getClass(), SAMLSSOException.class,
                        "Cause must be a SAMLSSOException.");
                assertEquals(((SAMLSSOException) cause).getErrorCode(), "SAM-65147",
                        "Error code must be SAM-65147 (METADATA_CERT_DECODE_FAILED).");
            }
        }
    }

    @Test(description = "When IdentityApplicationManagementUtil.decodeCertificate throws a CertificateException, "
            + "the original CertificateException should be set as the cause of the SAMLSSOException.")
    public void testDecodeCertificate_CertificateException_OriginalExceptionPreservedAsCause() throws Exception {

        CertificateException originalCause = new CertificateException("bad cert");

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenThrow(originalCause);

            try {
                invokeDecodeCertificate(VALID_BASE64_DER);
                throw new AssertionError("Expected SAMLSSOException was not thrown.");
            } catch (InvocationTargetException ite) {
                SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
                assertSame(samlEx.getCause(), originalCause,
                        "The original CertificateException must be the cause of the SAMLSSOException.");
            }
        }
    }

    /**
     * Invokes the private decodeCertificate method on the singleton instance via reflection.
     */
    private X509Certificate invokeDecodeCertificate(String base64Der) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("decodeCertificate", String.class);
        method.setAccessible(true);
        return (X509Certificate) method.invoke(SAMLMetadataCertificateResolver.getInstance(), base64Der);
    }

    @Test(description = "When SSOUtils.unmarshall returns an EntityDescriptor, "
            + "toEntityDescriptor should return that same instance.")
    public void testToEntityDescriptor_ValidEntityDescriptor_ReturnsSameInstance() throws Exception {

        EntityDescriptor mockEntityDescriptor = mock(EntityDescriptor.class);

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockEntityDescriptor);

            EntityDescriptor result = invokeToEntityDescriptor(RAW_METADATA, METADATA_URL);

            assertSame(result, mockEntityDescriptor, "Should return the EntityDescriptor returned by unmarshall.");
        }
    }

    @Test(description = "When SSOUtils.unmarshall returns a non-EntityDescriptor XMLObject, "
            + "toEntityDescriptor should throw SAMLSSOException.")
    public void testToEntityDescriptor_NonEntityDescriptorXmlObject_ThrowsSAMLSSOException() throws Exception {

        XMLObject mockXmlObject = mock(XMLObject.class);

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockXmlObject);

            try {
                invokeToEntityDescriptor(RAW_METADATA, METADATA_URL);
                throw new AssertionError("Expected SAMLSSOException was not thrown.");
            } catch (InvocationTargetException ite) {
                Throwable cause = ite.getCause();
                assertNotNull(cause, "InvocationTargetException must have a cause.");
                assertEquals(cause.getClass(), SAMLSSOException.class,
                        "Cause must be a SAMLSSOException.");
            }
        }
    }

    /**
     * Invokes the private toEntityDescriptor method on the singleton instance via reflection.
     */
    private EntityDescriptor invokeToEntityDescriptor(String rawMetadata, String metadataUrl) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("toEntityDescriptor", String.class, String.class);
        method.setAccessible(true);
        return (EntityDescriptor) method.invoke(SAMLMetadataCertificateResolver.getInstance(),
                rawMetadata, metadataUrl);
    }

    @Test(description = "When EntityDescriptor has no IDPSSODescriptor, "
            + "extractCertificates should return an empty list.")
    public void testExtractCertificates_NoIDPSSODescriptor_ReturnsEmptyList() throws Exception {

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.emptyList());

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertNotNull(result, "Result should not be null.");
        assertEquals(result.size(), 0, "Should return empty list when no IDPSSODescriptor is present.");
    }

    @Test(description = "When IDPSSODescriptor returns null for keyDescriptors, "
            + "extractCertificates should return an empty list.")
    public void testExtractCertificates_NullKeyDescriptors_ReturnsEmptyList() throws Exception {

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(null);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Should return empty list when keyDescriptors is null.");
    }

    @Test(description = "When a KeyDescriptor has a null use (unspecified), "
            + "it should be treated as a signing key and its certificate should be returned.")
    public void testExtractCertificates_NullUseKeyDescriptor_TreatedAsSigning() throws Exception {

        X509Certificate mockJavaCert = mock(X509Certificate.class);

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement.getValue()).thenReturn(VALID_BASE64_DER);

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement));

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(null);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenReturn(mockJavaCert);

            List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

            assertEquals(result.size(), 1,
                    "A KeyDescriptor with null use should be treated as signing and its certificate returned.");
            assertSame(result.get(0), mockJavaCert, "Should be the decoded certificate.");
        }
    }

    @Test(description = "When KeyDescriptors include one with null use and one with ENCRYPTION use, "
            + "only the null-use descriptor's certificate should be returned.")
    public void testExtractCertificates_NullUseAndEncryptionDescriptors_OnlyNullUseReturned() throws Exception {

        X509Certificate mockJavaCert = mock(X509Certificate.class);

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement.getValue()).thenReturn(VALID_BASE64_DER);

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement));

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor nullUseDescriptor = mock(KeyDescriptor.class);
        when(nullUseDescriptor.getUse()).thenReturn(null);
        when(nullUseDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        KeyDescriptor encryptionDescriptor = mock(KeyDescriptor.class);
        when(encryptionDescriptor.getUse()).thenReturn(UsageType.ENCRYPTION);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors())
                .thenReturn(Arrays.asList(nullUseDescriptor, encryptionDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenReturn(mockJavaCert);

            List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

            assertEquals(result.size(), 1,
                    "Only the null-use descriptor should contribute a certificate; ENCRYPTION should be skipped.");
            assertSame(result.get(0), mockJavaCert, "Should be the certificate from the null-use descriptor.");
        }
    }

    @Test(description = "When a KeyDescriptor has ENCRYPTION usage type, "
            + "it should be skipped and extractCertificates should return an empty list.")
    public void testExtractCertificates_EncryptionKeyDescriptor_Skipped() throws Exception {

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.ENCRYPTION);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Encryption key descriptor should be skipped.");
    }

    @Test(description = "When a SIGNING KeyDescriptor has null KeyInfo, "
            + "it should be skipped and extractCertificates should return an empty list.")
    public void testExtractCertificates_NullKeyInfo_Skipped() throws Exception {

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(null);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Null KeyInfo should be skipped.");
    }

    @Test(description = "When a SIGNING KeyDescriptor has KeyInfo with a null X509Data list, "
            + "it should be skipped and extractCertificates should return an empty list.")
    public void testExtractCertificates_NullX509DataList_Skipped() throws Exception {

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(null);

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Null X509Data list should be skipped.");
    }

    @Test(description = "When X509Data has a null certificates list, "
            + "it should be skipped and extractCertificates should return an empty list.")
    public void testExtractCertificates_NullX509Certificates_Skipped() throws Exception {

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(null);

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Null X509Certificates list should be skipped.");
    }

    @Test(description = "When an X509Certificate element has a blank value, "
            + "it should be skipped and extractCertificates should return an empty list.")
    public void testExtractCertificates_BlankCertValue_Skipped() throws Exception {

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement.getValue()).thenReturn("   ");

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement));

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

        assertEquals(result.size(), 0, "Blank certificate value should be skipped.");
    }

    @Test(description = "When a valid SIGNING KeyDescriptor with a certificate is present, "
            + "extractCertificates should return the decoded certificate.")
    public void testExtractCertificates_ValidSigningCert_ReturnsDecodedCertificate() throws Exception {

        X509Certificate mockJavaCert = mock(X509Certificate.class);

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement.getValue()).thenReturn(VALID_BASE64_DER);

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement));

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenReturn(mockJavaCert);

            List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

            assertEquals(result.size(), 1, "Should return exactly one certificate.");
            assertSame(result.get(0), mockJavaCert, "Should be the decoded certificate.");
        }
    }

    @Test(description = "When multiple certificates are present across multiple IDPSSODescriptors, "
            + "extractCertificates should return all of them.")
    public void testExtractCertificates_MultipleCerts_ReturnsAllCertificates() throws Exception {

        X509Certificate mockJavaCert1 = mock(X509Certificate.class);
        X509Certificate mockJavaCert2 = mock(X509Certificate.class);

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement1 =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement1.getValue()).thenReturn("CERTONE");

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement2 =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement2.getValue()).thenReturn("CERTTWO");

        X509Data mockX509Data1 = mock(X509Data.class);
        when(mockX509Data1.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement1));

        X509Data mockX509Data2 = mock(X509Data.class);
        when(mockX509Data2.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement2));

        KeyInfo mockKeyInfo1 = mock(KeyInfo.class);
        when(mockKeyInfo1.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data1));

        KeyInfo mockKeyInfo2 = mock(KeyInfo.class);
        when(mockKeyInfo2.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data2));

        KeyDescriptor mockKeyDescriptor1 = mock(KeyDescriptor.class);
        when(mockKeyDescriptor1.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor1.getKeyInfo()).thenReturn(mockKeyInfo1);

        KeyDescriptor mockKeyDescriptor2 = mock(KeyDescriptor.class);
        when(mockKeyDescriptor2.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor2.getKeyInfo()).thenReturn(mockKeyInfo2);

        IDPSSODescriptor mockIdpDescriptor1 = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor1.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor1));

        IDPSSODescriptor mockIdpDescriptor2 = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor2.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor2));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any()))
                .thenReturn(Arrays.asList(mockIdpDescriptor1, mockIdpDescriptor2));

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate("CERTONE"))
                    .thenReturn(mockJavaCert1);
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate("CERTTWO"))
                    .thenReturn(mockJavaCert2);

            List<X509Certificate> result = invokeExtractCertificates(mockDescriptor);

            assertEquals(result.size(), 2, "Should return two certificates.");
            assertTrue(result.contains(mockJavaCert1), "Should contain the first certificate.");
            assertTrue(result.contains(mockJavaCert2), "Should contain the second certificate.");
        }
    }

    @Test(description = "When decodeCertificate fails, "
            + "extractCertificates should propagate the SAMLSSOException.")
    public void testExtractCertificates_DecodeCertificateFails_PropagatesSAMLSSOException() throws Exception {

        org.opensaml.xmlsec.signature.X509Certificate mockCertElement =
                mock(org.opensaml.xmlsec.signature.X509Certificate.class);
        when(mockCertElement.getValue()).thenReturn(VALID_BASE64_DER);

        X509Data mockX509Data = mock(X509Data.class);
        when(mockX509Data.getX509Certificates()).thenReturn(Collections.singletonList(mockCertElement));

        KeyInfo mockKeyInfo = mock(KeyInfo.class);
        when(mockKeyInfo.getX509Datas()).thenReturn(Collections.singletonList(mockX509Data));

        KeyDescriptor mockKeyDescriptor = mock(KeyDescriptor.class);
        when(mockKeyDescriptor.getUse()).thenReturn(UsageType.SIGNING);
        when(mockKeyDescriptor.getKeyInfo()).thenReturn(mockKeyInfo);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.singletonList(mockKeyDescriptor));

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.singletonList(mockIdpDescriptor));

        try (MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(anyString()))
                    .thenThrow(new CertificateException("invalid cert"));

            try {
                invokeExtractCertificates(mockDescriptor);
                throw new AssertionError("Expected SAMLSSOException was not thrown.");
            } catch (InvocationTargetException ite) {
                assertEquals(ite.getCause().getClass(), SAMLSSOException.class,
                        "Should propagate SAMLSSOException from decodeCertificate.");
            }
        }
    }

    /**
     * Invokes the private extractCertificates method on the singleton instance via reflection.
     */
    @SuppressWarnings("unchecked")
    private List<X509Certificate> invokeExtractCertificates(EntityDescriptor entityDescriptor) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("extractCertificates", EntityDescriptor.class);
        method.setAccessible(true);
        return (List<X509Certificate>) method.invoke(SAMLMetadataCertificateResolver.getInstance(),
                entityDescriptor);
    }

    @Test(description = "When callAPI returns HTTP 200 with a non-blank body, "
            + "fetchMetadata should return that body.")
    public void testFetchMetadata_200WithBody_ReturnsBody() throws Exception {

        String expectedBody = "<EntityDescriptor>...</EntityDescriptor>";
        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, expectedBody)).when(spy).callAPI(any(), any());

        String result = invokeFetchMetadata(spy, METADATA_URL);

        assertEquals(result, expectedBody, "Should return the response body on HTTP 200.");
    }

    @Test(description = "When callAPI returns a non-200 HTTP status, "
            + "fetchMetadata should throw SAMLSSOException with error code SAM-65142.")
    public void testFetchMetadata_Non200Status_ErrorCodeIsSAM65142() throws Exception {

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(404, null)).when(spy).callAPI(any(), any());

        try {
            invokeFetchMetadata(spy, METADATA_URL);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (InvocationTargetException ite) {
            SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
            assertEquals(samlEx.getErrorCode(), "SAM-65142",
                    "Error code must be SAM-65142 (METADATA_FETCH_HTTP_ERROR).");
        }
    }

    @Test(description = "When callAPI returns HTTP 200 but an empty body, "
            + "fetchMetadata should throw SAMLSSOException with error code SAM-65143.")
    public void testFetchMetadata_EmptyResponseBody_ErrorCodeIsSAM65143() throws Exception {

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, "")).when(spy).callAPI(any(), any());

        try {
            invokeFetchMetadata(spy, METADATA_URL);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (InvocationTargetException ite) {
            SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
            assertEquals(samlEx.getErrorCode(), "SAM-65143",
                    "Error code must be SAM-65143 (METADATA_EMPTY_RESPONSE_BODY).");
        }
    }

    @Test(description = "When callAPI returns HTTP 200 but a whitespace-only body, "
            + "fetchMetadata should throw SAMLSSOException with error code SAM-65143.")
    public void testFetchMetadata_BlankResponseBody_ErrorCodeIsSAM65143() throws Exception {

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, "   ")).when(spy).callAPI(any(), any());

        try {
            invokeFetchMetadata(spy, METADATA_URL);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (InvocationTargetException ite) {
            SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
            assertEquals(samlEx.getErrorCode(), "SAM-65143",
                    "Error code must be SAM-65143 (METADATA_EMPTY_RESPONSE_BODY).");
        }
    }

    @Test(description = "When callAPI throws an APIClientException, "
            + "fetchMetadata should throw SAMLSSOException with error code SAM-65144.")
    public void testFetchMetadata_APIClientException_ErrorCodeIsSAM65144() throws Exception {

        APIClientException mockApiClientException = mock(APIClientException.class);
        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doThrow(mockApiClientException).when(spy).callAPI(any(), any());

        try {
            invokeFetchMetadata(spy, METADATA_URL);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (InvocationTargetException ite) {
            SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
            assertEquals(samlEx.getErrorCode(), "SAM-65144",
                    "Error code must be SAM-65144 (METADATA_FETCH_FAILED).");
        }
    }

    @Test(description = "When callAPI throws an APIClientException, "
            + "the original exception should be preserved as the cause of the SAMLSSOException.")
    public void testFetchMetadata_APIClientException_OriginalExceptionPreservedAsCause() throws Exception {

        APIClientException mockApiClientException = mock(APIClientException.class);
        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doThrow(mockApiClientException).when(spy).callAPI(any(), any());

        try {
            invokeFetchMetadata(spy, METADATA_URL);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (InvocationTargetException ite) {
            SAMLSSOException samlEx = (SAMLSSOException) ite.getCause();
            assertSame(samlEx.getCause(), mockApiClientException,
                    "The original APIClientException must be the cause of the SAMLSSOException.");
        }
    }

    /**
     * Invokes the private fetchMetadata method on the given instance via reflection.
     */
    private String invokeFetchMetadata(SAMLMetadataCertificateResolver instance, String metadataUrl)
            throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("fetchMetadata", String.class);
        method.setAccessible(true);
        return (String) method.invoke(instance, metadataUrl);
    }

    @Test(description = "When the metadata URL is blank, "
            + "getSigningCertificatesFromMetadata should throw SAMLSSOException with error code SAM-65141.")
    public void testGetSigningCertificatesFromMetadata_BlankUrl_ErrorCodeIsSAM65141() {

        try {
            SAMLMetadataCertificateResolver.getInstance()
                    .getSigningCertificatesFromMetadata("  ", ENTITY_ID);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(), "SAM-65141",
                    "Error code must be SAM-65141 (METADATA_URL_BLANK).");
        }
    }

    @Test(description = "When the metadata URL is null, "
            + "getSigningCertificatesFromMetadata should throw SAMLSSOException with error code SAM-65141.")
    public void testGetSigningCertificatesFromMetadata_NullUrl_ErrorCodeIsSAM65141() {

        try {
            SAMLMetadataCertificateResolver.getInstance()
                    .getSigningCertificatesFromMetadata(null, ENTITY_ID);
            throw new AssertionError("Expected SAMLSSOException was not thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(), "SAM-65141",
                    "Error code must be SAM-65141 (METADATA_URL_BLANK).");
        }
    }

    @Test(description = "When the entity ID in the metadata does not match, "
            + "the error code should be SAM-65148.")
    public void testGetSigningCertificatesFromMetadata_EntityIdMismatch_ErrorCodeIsSAM65148()
            throws Exception {

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getEntityID()).thenReturn("https://other-idp.example.com");
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.emptyList());

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, RAW_METADATA)).when(spy).callAPI(any(), any());

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockDescriptor);

            try {
                spy.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);
                throw new AssertionError("Expected SAMLSSOException was not thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(), "SAM-65148",
                        "Error code must be SAM-65148 (METADATA_ENTITY_ID_MISMATCH).");
            }
        }
    }

    @Test(description = "When inputs are valid and entity IDs match, "
            + "getSigningCertificatesFromMetadata should return a non-null RemoteCertificate with certificates.")
    public void testGetSigningCertificatesFromMetadata_MatchingEntityId_ReturnsRemoteCertificate()
            throws Exception {

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getEntityID()).thenReturn(ENTITY_ID);
        when(mockDescriptor.getValidUntil()).thenReturn(null);
        when(mockDescriptor.getCacheDuration()).thenReturn(null);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.emptyList());

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, RAW_METADATA)).when(spy).callAPI(any(), any());

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockDescriptor);

            RemoteCertificate result = spy.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);

            assertNotNull(result, "RemoteCertificate must not be null.");
            assertNotNull(result.getCertificates(), "Certificates list must not be null.");
        }
    }

    @Test(description = "When the EntityDescriptor has a validUntil value, "
            + "getSigningCertificatesFromMetadata should map it to an Instant in the RemoteCertificate.")
    public void testGetSigningCertificatesFromMetadata_WithValidUntil_PopulatesValidUntil()
            throws Exception {

        long validUntilMillis = 1234567890000L;
        DateTime mockValidUntil = mock(DateTime.class);
        when(mockValidUntil.getMillis()).thenReturn(validUntilMillis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getEntityID()).thenReturn(ENTITY_ID);
        when(mockDescriptor.getValidUntil()).thenReturn(mockValidUntil);
        when(mockDescriptor.getCacheDuration()).thenReturn(null);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.emptyList());

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, RAW_METADATA)).when(spy).callAPI(any(), any());

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockDescriptor);

            RemoteCertificate result = spy.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);

            assertEquals(result.getValidUntil(), Instant.ofEpochMilli(validUntilMillis),
                    "validUntil should be mapped correctly from the EntityDescriptor.");
        }
    }

    @Test(description = "When the EntityDescriptor has a cacheDuration value, "
            + "getSigningCertificatesFromMetadata should map it to a Duration in the RemoteCertificate.")
    public void testGetSigningCertificatesFromMetadata_WithCacheDuration_PopulatesCacheDuration()
            throws Exception {

        long cacheDurationMillis = 3600000L;

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getEntityID()).thenReturn(ENTITY_ID);
        when(mockDescriptor.getValidUntil()).thenReturn(null);
        when(mockDescriptor.getCacheDuration()).thenReturn(cacheDurationMillis);
        when(mockDescriptor.getRoleDescriptors(any())).thenReturn(Collections.emptyList());

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, RAW_METADATA)).when(spy).callAPI(any(), any());

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockDescriptor);

            RemoteCertificate result = spy.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);

            assertEquals(result.getCacheDuration(), Duration.ofMillis(cacheDurationMillis),
                    "cacheDuration should be mapped correctly from the EntityDescriptor.");
        }
    }

    @Test(description = "When both EntityDescriptor and all IDPSSODescriptors have null validUntil, "
            + "resolveEffectiveValidUntil should return null.")
    public void testResolveEffectiveValidUntil_BothNull_ReturnsNull() throws Exception {

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(null);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(null);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertNull(result, "Should return null when no validUntil is set anywhere.");
    }

    @Test(description = "When only the EntityDescriptor has a validUntil and IDPSSODescriptor has none, "
            + "resolveEffectiveValidUntil should return the EntityDescriptor's value.")
    public void testResolveEffectiveValidUntil_OnlyEntityDescriptor_ReturnsEntityDescriptorValue()
            throws Exception {

        long millis = 1000000000000L;
        DateTime mockDateTime = mock(DateTime.class);
        when(mockDateTime.getMillis()).thenReturn(millis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(mockDateTime);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(null);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Instant.ofEpochMilli(millis),
                "Should return the EntityDescriptor's validUntil when IDPSSODescriptor has none.");
    }

    @Test(description = "When only the IDPSSODescriptor has a validUntil and EntityDescriptor has none, "
            + "resolveEffectiveValidUntil should return the IDPSSODescriptor's value.")
    public void testResolveEffectiveValidUntil_OnlyIDPSSODescriptor_ReturnsIDPSSODescriptorValue()
            throws Exception {

        long idpMillis = 2000000000000L;
        DateTime mockIdpDateTime = mock(DateTime.class);
        when(mockIdpDateTime.getMillis()).thenReturn(idpMillis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(null);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(mockIdpDateTime);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Instant.ofEpochMilli(idpMillis),
                "Should return the IDPSSODescriptor's validUntil when EntityDescriptor has none.");
    }

    @Test(description = "When the IDPSSODescriptor has an earlier validUntil than the EntityDescriptor, "
            + "resolveEffectiveValidUntil should return the IDPSSODescriptor's (earlier) value.")
    public void testResolveEffectiveValidUntil_IDPSSODescriptorEarlier_ReturnsIDPSSODescriptorValue()
            throws Exception {

        long entityMillis = 2000000000000L; // later.
        long idpMillis    = 1000000000000L; // earlier.

        DateTime mockEntityDateTime = mock(DateTime.class);
        when(mockEntityDateTime.getMillis()).thenReturn(entityMillis);

        DateTime mockIdpDateTime = mock(DateTime.class);
        when(mockIdpDateTime.getMillis()).thenReturn(idpMillis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(mockEntityDateTime);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(mockIdpDateTime);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Instant.ofEpochMilli(idpMillis),
                "IDPSSODescriptor's earlier validUntil should win over EntityDescriptor's later value.");
    }

    @Test(description = "When the EntityDescriptor has an earlier validUntil than the IDPSSODescriptor, "
            + "resolveEffectiveValidUntil should return the EntityDescriptor's (earlier) value.")
    public void testResolveEffectiveValidUntil_EntityDescriptorEarlier_ReturnsEntityDescriptorValue()
            throws Exception {

        long entityMillis = 1000000000000L; // earlier.
        long idpMillis    = 2000000000000L; // later.

        DateTime mockEntityDateTime = mock(DateTime.class);
        when(mockEntityDateTime.getMillis()).thenReturn(entityMillis);

        DateTime mockIdpDateTime = mock(DateTime.class);
        when(mockIdpDateTime.getMillis()).thenReturn(idpMillis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(mockEntityDateTime);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(mockIdpDateTime);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Instant.ofEpochMilli(entityMillis),
                "EntityDescriptor's earlier validUntil should win over IDPSSODescriptor's later value.");
    }

    @Test(description = "When multiple IDPSSODescriptors are present, "
            + "resolveEffectiveValidUntil should return the earliest value across all of them.")
    public void testResolveEffectiveValidUntil_MultipleIDPSSODescriptors_ReturnsEarliest()
            throws Exception {

        long entityMillis = 3000000000000L;
        long idp1Millis   = 1000000000000L; // earliest.
        long idp2Millis   = 2000000000000L;

        DateTime mockEntityDateTime = mock(DateTime.class);
        when(mockEntityDateTime.getMillis()).thenReturn(entityMillis);

        DateTime mockIdp1DateTime = mock(DateTime.class);
        when(mockIdp1DateTime.getMillis()).thenReturn(idp1Millis);

        DateTime mockIdp2DateTime = mock(DateTime.class);
        when(mockIdp2DateTime.getMillis()).thenReturn(idp2Millis);

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getValidUntil()).thenReturn(mockEntityDateTime);

        IDPSSODescriptor mockIdp1 = mock(IDPSSODescriptor.class);
        when(mockIdp1.getValidUntil()).thenReturn(mockIdp1DateTime);

        IDPSSODescriptor mockIdp2 = mock(IDPSSODescriptor.class);
        when(mockIdp2.getValidUntil()).thenReturn(mockIdp2DateTime);

        Instant result = invokeResolveEffectiveValidUntil(mockDescriptor,
                Arrays.asList(mockIdp1, mockIdp2));

        assertEquals(result, Instant.ofEpochMilli(idp1Millis),
                "Should return the globally earliest validUntil across all descriptors.");
    }

    /**
     * Invokes the private resolveEffectiveValidUntil method via reflection.
     */
    private Instant invokeResolveEffectiveValidUntil(EntityDescriptor entityDescriptor,
            List<IDPSSODescriptor> idpDescriptors) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("resolveEffectiveValidUntil", EntityDescriptor.class, List.class);
        method.setAccessible(true);
        return (Instant) method.invoke(SAMLMetadataCertificateResolver.getInstance(),
                entityDescriptor, idpDescriptors);
    }

    @Test(description = "When both EntityDescriptor and all IDPSSODescriptors have null cacheDuration, "
            + "resolveEffectiveCacheDuration should return null.")
    public void testResolveEffectiveCacheDuration_BothNull_ReturnsNull() throws Exception {

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(null);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(null);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertNull(result, "Should return null when no cacheDuration is set anywhere.");
    }

    @Test(description = "When only the EntityDescriptor has a cacheDuration and IDPSSODescriptor has none, "
            + "resolveEffectiveCacheDuration should return the EntityDescriptor's value.")
    public void testResolveEffectiveCacheDuration_OnlyEntityDescriptor_ReturnsEntityDescriptorValue()
            throws Exception {

        long entityDuration = 7200000L;

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(entityDuration);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(null);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Duration.ofMillis(entityDuration),
                "Should return the EntityDescriptor's cacheDuration when IDPSSODescriptor has none.");
    }

    @Test(description = "When only the IDPSSODescriptor has a cacheDuration and EntityDescriptor has none, "
            + "resolveEffectiveCacheDuration should return the IDPSSODescriptor's value.")
    public void testResolveEffectiveCacheDuration_OnlyIDPSSODescriptor_ReturnsIDPSSODescriptorValue()
            throws Exception {

        long idpDuration = 3600000L;

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(null);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(idpDuration);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Duration.ofMillis(idpDuration),
                "Should return the IDPSSODescriptor's cacheDuration when EntityDescriptor has none.");
    }

    @Test(description = "When the IDPSSODescriptor has a shorter cacheDuration than the EntityDescriptor, "
            + "resolveEffectiveCacheDuration should return the IDPSSODescriptor's (shorter) value.")
    public void testResolveEffectiveCacheDuration_IDPSSODescriptorShorter_ReturnsIDPSSODescriptorValue()
            throws Exception {

        long entityDuration = 7200000L; // longer.
        long idpDuration    = 1800000L; // shorter.

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(entityDuration);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(idpDuration);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Duration.ofMillis(idpDuration),
                "IDPSSODescriptor's shorter cacheDuration should win over EntityDescriptor's longer value.");
    }

    @Test(description = "When the EntityDescriptor has a shorter cacheDuration than the IDPSSODescriptor, "
            + "resolveEffectiveCacheDuration should return the EntityDescriptor's (shorter) value.")
    public void testResolveEffectiveCacheDuration_EntityDescriptorShorter_ReturnsEntityDescriptorValue()
            throws Exception {

        long entityDuration = 1800000L; // shorter.
        long idpDuration    = 7200000L; // longer.

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(entityDuration);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(idpDuration);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Collections.singletonList(mockIdpDescriptor));

        assertEquals(result, Duration.ofMillis(entityDuration),
                "EntityDescriptor's shorter cacheDuration should win over IDPSSODescriptor's longer value.");
    }

    @Test(description = "When multiple IDPSSODescriptors are present, "
            + "resolveEffectiveCacheDuration should return the shortest value across all of them.")
    public void testResolveEffectiveCacheDuration_MultipleIDPSSODescriptors_ReturnsShortest()
            throws Exception {

        long entityDuration = 7200000L;
        long idp1Duration   =  900000L; // shortest.
        long idp2Duration   = 3600000L;

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getCacheDuration()).thenReturn(entityDuration);

        IDPSSODescriptor mockIdp1 = mock(IDPSSODescriptor.class);
        when(mockIdp1.getCacheDuration()).thenReturn(idp1Duration);

        IDPSSODescriptor mockIdp2 = mock(IDPSSODescriptor.class);
        when(mockIdp2.getCacheDuration()).thenReturn(idp2Duration);

        Duration result = invokeResolveEffectiveCacheDuration(mockDescriptor,
                Arrays.asList(mockIdp1, mockIdp2));

        assertEquals(result, Duration.ofMillis(idp1Duration),
                "Should return the globally shortest cacheDuration across all descriptors.");
    }

    /**
     * Invokes the private resolveEffectiveCacheDuration method via reflection.
     */
    private Duration invokeResolveEffectiveCacheDuration(EntityDescriptor entityDescriptor,
            List<IDPSSODescriptor> idpDescriptors) throws Exception {

        Method method = SAMLMetadataCertificateResolver.class
                .getDeclaredMethod("resolveEffectiveCacheDuration", EntityDescriptor.class, List.class);
        method.setAccessible(true);
        return (Duration) method.invoke(SAMLMetadataCertificateResolver.getInstance(),
                entityDescriptor, idpDescriptors);
    }

    @Test(description = "When the IDPSSODescriptor has an earlier validUntil than the EntityDescriptor, "
            + "getSigningCertificatesFromMetadata should use the IDPSSODescriptor's value.")
    public void testGetSigningCertificatesFromMetadata_IDPSSODescriptorEarlierValidUntil_UsesIDPSSODescriptorValue()
            throws Exception {

        long entityMillis = 2000000000000L; // later.
        long idpMillis    = 1000000000000L; // earlier.

        DateTime mockEntityDateTime = mock(DateTime.class);
        when(mockEntityDateTime.getMillis()).thenReturn(entityMillis);

        DateTime mockIdpDateTime = mock(DateTime.class);
        when(mockIdpDateTime.getMillis()).thenReturn(idpMillis);

        IDPSSODescriptor mockIdpDescriptor = mock(IDPSSODescriptor.class);
        when(mockIdpDescriptor.getValidUntil()).thenReturn(mockIdpDateTime);
        when(mockIdpDescriptor.getCacheDuration()).thenReturn(null);
        when(mockIdpDescriptor.getKeyDescriptors()).thenReturn(Collections.emptyList());

        EntityDescriptor mockDescriptor = mock(EntityDescriptor.class);
        when(mockDescriptor.getEntityID()).thenReturn(ENTITY_ID);
        when(mockDescriptor.getValidUntil()).thenReturn(mockEntityDateTime);
        when(mockDescriptor.getCacheDuration()).thenReturn(null);
        when(mockDescriptor.getRoleDescriptors(any()))
                .thenReturn(Collections.singletonList(mockIdpDescriptor));

        SAMLMetadataCertificateResolver spy = spy(SAMLMetadataCertificateResolver.getInstance());
        doReturn(new APIResponse(200, RAW_METADATA)).when(spy).callAPI(any(), any());

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class)) {
            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            ssoUtilsMock.when(() -> SSOUtils.unmarshall(RAW_METADATA))
                    .thenReturn(mockDescriptor);

            RemoteCertificate result = spy.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);

            assertEquals(result.getValidUntil(), Instant.ofEpochMilli(idpMillis),
                    "IDPSSODescriptor's earlier validUntil should be used.");
        }
    }
}
