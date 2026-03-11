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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;

public class SAMLMetadataCertificateResolverTest {

    private static final String TEST_PARAM = "TestParam";
    private static final int INT_DEFAULT = 100;
    private static final long LONG_DEFAULT = 200L;

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

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class);
             MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {

            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
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

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class);
             MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {

            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
            utilMock.when(() -> IdentityApplicationManagementUtil.decodeCertificate(expectedCleaned))
                    .thenReturn(mockCert);

            X509Certificate result = invokeDecodeCertificate(inputWithWhitespace);

            assertSame(result, mockCert, "Should pass the whitespace-stripped value to the utility.");
        }
    }

    @Test(description = "When IdentityApplicationManagementUtil.decodeCertificate throws a CertificateException, "
            + "decodeCertificate should wrap it in a SAMLSSOException with error code SAM-65147.")
    public void testDecodeCertificate_CertificateException_ThrowsSAMLSSOException() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class);
             MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {

            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
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

        try (MockedStatic<SSOUtils> ssoUtilsMock = mockStatic(SSOUtils.class);
             MockedStatic<IdentityApplicationManagementUtil> utilMock =
                     mockStatic(IdentityApplicationManagementUtil.class)) {

            ssoUtilsMock.when(() -> SSOUtils.getAuthenticatorParamMap(anyString()))
                    .thenReturn(Collections.emptyMap());
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
}
