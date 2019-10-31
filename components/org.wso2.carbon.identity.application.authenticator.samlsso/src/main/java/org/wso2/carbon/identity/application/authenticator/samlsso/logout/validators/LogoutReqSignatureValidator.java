/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SIGNATURE;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SIGNATURE_ALGORITHM;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.
        HTTP_POST_PARAM_SAML2_AUTH_REQ;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.RELAY_STATE;

/**
 * This class is used to validate the signature in SAML logout Request.
 */
public class LogoutReqSignatureValidator {

    private static final Log log = LogFactory.getLog(LogoutReqSignatureValidator.class);

    /**
     * Validates the signature of the SAML requests sent with HTTP Redirect Binding against the given certificate.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @param issuer      Issuer of the SAML request.
     * @param certificate Certificate for validating the signature
     * @return true       If the signature is valid, false otherwise.
     * @throws SecurityException if something goes wrong during signature validation.
     */
    public boolean validateSignature(String queryString, String issuer, X509Certificate certificate)
            throws SecurityException {

        byte[] signature = getSignature(queryString);
        byte[] signedContent = getSignedContent(queryString);
        String algorithmUri = getSignatureAlgorithm(queryString);
        CriteriaSet criteriaSet = buildCriteriaSet(issuer);

        X509CredentialImpl credential = new X509CredentialImpl(certificate);
        List<Credential> credentials = new ArrayList<Credential>();
        credentials.add(credential);
        CollectionCredentialResolver credentialResolver = new CollectionCredentialResolver(credentials);
        KeyInfoCredentialResolver keyResolver = SecurityHelper.buildBasicInlineKeyInfoResolver();
        SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyResolver);
        return engine.validate(signature, signedContent, algorithmUri, criteriaSet, null);
    }

    /**
     * Validate the  Signature in the SAML Assertion.
     *
     * @param request SAML Assertion (SAML LogoutRequest).
     * @param cred    Signature signing credential.
     * @param alias   Certificate alias against which the signature is validated.
     * @return true,  If the signature is valid.
     * @throws IdentityException If something goes wrong during signature validation.
     */
    public boolean validateXMLSignature(SignableXMLObject request, X509Credential cred,
                                        String alias) throws IdentityException {

        if (request.getSignature() != null) {
            try {
                org.opensaml.xml.signature.SignatureValidator validator =
                        new org.opensaml.xml.signature.SignatureValidator(cred);
                validator.validate(request.getSignature());
                return true;
            } catch (ValidationException e) {
                throw IdentityException.error("Signature Validation Failed for the SAML Assertion", e);
            }
        }
        return false;
    }

    /**
     * Build a criteria set suitable for input to the trust engine.
     *
     * @param issuer Issuer of the SAML request.
     * @return CriteriaSet.
     */
    private static CriteriaSet buildCriteriaSet(String issuer) {

        CriteriaSet criteriaSet = new CriteriaSet();
        if (StringUtils.isNotEmpty(issuer)) {
            criteriaSet.add(new EntityIDCriteria(issuer));
        }
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        return criteriaSet;
    }

    /**
     * Extract the signature algorithm from the query string in the request.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return String     Signature Algorithm of the request.
     * @throws SecurityPolicyException If process of extracting signature algorithm fails.
     */
    private static String getSignatureAlgorithm(String queryString) throws SecurityPolicyException {

        String sigAlgQueryParam = HTTPTransportUtils.getRawQueryStringParameter(queryString, SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(sigAlgQueryParam)) {
            throw new SecurityPolicyException("Could'nt extract Signature Algorithm from query string: " + queryString);
        }

        try {
            /* Split 'SigAlg=<sigalg_value>' query param using '=' as the delimiter,
            and get the Signature Algorithm. */
            return URLDecoder.decode(sigAlgQueryParam.split("=")[1], StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Encoding not supported.", e);
            }
            return null;
        }
    }

    /**
     * Extract the signature value from the request.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return byte[]     Base64-decoded value of the HTTP request signature parameter.
     * @throws SecurityPolicyException If process of extracting signature fails.
     */
    private static byte[] getSignature(String queryString) throws SecurityPolicyException {

        String signatureQueryParam = HTTPTransportUtils.getRawQueryStringParameter(queryString, SIGNATURE);
        if (StringUtils.isEmpty(signatureQueryParam)) {
            throw new SecurityPolicyException("Could not extract the Signature from query string: " + queryString);
        }

        try {
            /* Split 'Signature=<sig_value>' query param using '=' as the delimiter,
		      and get the Signature value. */
            return Base64.decode(URLDecoder.decode(signatureQueryParam.split("=")[1],
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Encoding not supported.", e);
            }
            // JVM is required to support UTF-8
            return new byte[0];
        }
    }

    /**
     * Extract the signed content string from the query string in the request.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return byte[]     Signed content.
     * @throws SecurityPolicyException If process of constructing signed content fails.
     */
    private static byte[] getSignedContent(String queryString) throws SecurityPolicyException {

        if (log.isDebugEnabled()) {
            log.debug("Constructing signed content string from URL query string " + queryString);
        }
        String constructed = buildSignedContentString(queryString);
        if (StringUtils.isEmpty(constructed)) {
            throw new SecurityPolicyException(
                    "Could not extract signed content string from query string");
        }
        if (log.isDebugEnabled()) {
            log.debug("Constructed signed content string for HTTP-Redirect DEFLATE " + constructed);
        }
        return constructed.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Extract the raw request parameters and build a string representation of
     * the content that was signed.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return String     Representation of the signed content.
     * @throws SecurityPolicyException thrown if there is an error during request processing.
     */
    private static String buildSignedContentString(String queryString) throws SecurityPolicyException {

        StringBuilder builder = new StringBuilder();

        if (StringUtils.isBlank(HTTPTransportUtils.getRawQueryStringParameter(queryString,
                HTTP_POST_PARAM_SAML2_AUTH_REQ))) {
            throw new SecurityPolicyException("Extract of SAMLRequest or SAMLResponse from query string failed");
        }
        appendParameter(builder, queryString, HTTP_POST_PARAM_SAML2_AUTH_REQ);
        // This is optional.
        appendParameter(builder, queryString, RELAY_STATE);
        // This is mandatory, but has already been checked in superclass.
        appendParameter(builder, queryString, SIGNATURE_ALGORITHM);

        return builder.toString();
    }

    /**
     * Append raw query string parameter it to the string builder.
     *
     * @param builder     String builder to which to append the parameter
     * @param queryString The URL query string containing parameters
     * @param paramName   The name of the parameter to append
     * @return true       If raw string of parameter is not null.
     */
    private static boolean appendParameter(StringBuilder builder, String queryString,
                                           String paramName) {

        String rawParam = HTTPTransportUtils.getRawQueryStringParameter(queryString, paramName);
        if (rawParam == null) {
            return false;
        }
        if (builder.length() > 0) {
            builder.append('&');
        }
        builder.append(rawParam);
        return true;
    }
}
