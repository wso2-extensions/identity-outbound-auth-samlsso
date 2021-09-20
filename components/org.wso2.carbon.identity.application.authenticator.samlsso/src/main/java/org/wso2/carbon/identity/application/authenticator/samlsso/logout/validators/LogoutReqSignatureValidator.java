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

import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.apache.commons.lang.StringUtils;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.SecurityException;
import net.shibboleth.utilities.java.support.net.URISupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.RELAY_STATE;

/**
 * This class is used to validate the signature in SAML logout Request.
 */
public class LogoutReqSignatureValidator {

    private static final Log log = LogFactory.getLog(LogoutReqSignatureValidator.class);

    /**
     * Validates the signature of the SAML requests sent with HTTP Redirect Binding against the given certificate.
     *
     * @param queryString SAML request (passed as an HTTP query parameter).
     * @param issuer      Issuer of the SAML request.
     * @param certificate Certificate for validating the signature.
     * @return true       If the signature is valid, false otherwise.
     * @throws SecurityException If signature validation process fails.
     */
    public boolean validateSignature(String queryString, String issuer, X509Certificate certificate)
            throws SecurityException, IdentityException {

        byte[] signature = getSignature(queryString);
        byte[] signedContent = getSignedContent(queryString);
        String algorithmUri = getSignatureAlgorithm(queryString);
        CriteriaSet criteriaSet = buildCriteriaSet(issuer);

        // creating the SAML2HTTPRedirectDeflateSignatureRule
        X509CredentialImpl credential = new X509CredentialImpl(certificate, issuer);

        List<Credential> credentials = new ArrayList<Credential>();
        credentials.add(credential);
        CollectionCredentialResolver credentialResolver = new CollectionCredentialResolver(credentials);
        KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap.
                buildBasicInlineKeyInfoCredentialResolver();
        SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credentialResolver, keyResolver);
        return engine.validate(signature, signedContent, algorithmUri, criteriaSet, null);
    }

    /**
     * Validate the  Signature in the SAML Assertion.
     *
     * @param request SAML Assertion (SAML LogoutRequest).
     * @param cred    Signature signing credential.
     * @return true   If the signature is valid.
     * @throws IdentityException If signature validation process fails.
     */
    public boolean validateXMLSignature(SignableXMLObject request, X509Credential cred) throws IdentityException {

        if (request.getSignature() != null) {
            try {
                SignatureValidator.validate(request.getSignature(), cred);
                return true;
            } catch (SignatureException e) {
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
        if (StringUtils.isNotBlank(issuer)) {
            criteriaSet.add(new EntityIdCriterion(issuer));
        }
        criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
        return criteriaSet;
    }

    /**
     * Extract the signature algorithm from the query string in the request.
     *
     * @param queryString SAML request (passed as an HTTP query parameter).
     * @return String     Signature Algorithm of the request.
     * @throws SecurityException If process of extracting signature algorithm fails.
     * @throws IdentityException If decoding not supported.
     */
    private static String getSignatureAlgorithm(String queryString) throws SecurityException,
            IdentityException {

        String sigAlgQueryParam = URISupport.getRawQueryStringParameter(queryString, SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(sigAlgQueryParam)) {
            throw new SecurityException("Couldn't extract signature algorithm from query string: " + queryString);
        }

        try {
            // Split 'SigAlg=<sigalg_value>' query param using '=' as the delimiter,and get the Signature Algorithm.
            if (StringUtils.isNotBlank(sigAlgQueryParam.split("=")[1])) {
                return URLDecoder.decode(sigAlgQueryParam.split("=")[1], StandardCharsets.UTF_8.name());
            }
            throw new SecurityException("Couldn't extract the signature algorithm value from the query string " +
                    "parameter: " + sigAlgQueryParam);
        } catch (UnsupportedEncodingException e) {
            throw new IdentityException("Error occurred while decoding signature algorithm query parameter: "
                    + sigAlgQueryParam, e);
        }
    }

    /**
     * Extract the signature value from the request.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return byte[]     Base64-decoded value of the HTTP request signature parameter.
     * @throws SecurityException If process of extracting signature fails.
     */
    private static byte[] getSignature(String queryString) throws SecurityException, IdentityException {

        String signatureQueryParam = URISupport.getRawQueryStringParameter(queryString, SIGNATURE);
        if (StringUtils.isEmpty(signatureQueryParam)) {
            throw new SecurityException("Couldn't extract the Signature from query string: " + queryString);
        }

        try {
            // Split 'Signature=<sig_value>' query param using '=' as the delimiter,and get the Signature value.
            if (StringUtils.isNotBlank(signatureQueryParam.split("=")[1])) {
                return Base64Support.decode(URLDecoder.decode(signatureQueryParam.split("=")[1],
                        StandardCharsets.UTF_8.name()));
            }
            throw new SecurityException("Couldn't extract the signature value from the query string parameter: "
                    + signatureQueryParam);
        } catch (UnsupportedEncodingException e) {
            throw new IdentityException("Error occurred while decoding signature query parameter: "
                    + signatureQueryParam, e);
        }
    }

    /**
     * Extract the signed content string from the query string in the request.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return byte[]     Signed content.
     * @throws SecurityException If process of constructing signed content fails.
     */
    private static byte[] getSignedContent(String queryString) throws SecurityException {

        String sigendContent = buildSignedContentString(queryString);
        if (StringUtils.isEmpty(sigendContent)) {
            String message = "Couldn't extract signed content string from query string: " + queryString;
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            throw new SecurityException(message);
        }
        return sigendContent.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Extract the raw request parameters and build a string representation of
     * the content that was signed.
     *
     * @param queryString SAML request (passed an an HTTP query parameter).
     * @return String     Representation of the signed content.
     * @throws SecurityException thrown if there is an error during request processing.
     */
    private static String buildSignedContentString(String queryString) throws SecurityException {

        StringBuilder builder = new StringBuilder();
        if (StringUtils.isBlank(URISupport.getRawQueryStringParameter(queryString,
                HTTP_POST_PARAM_SAML2_AUTH_REQ))) {
            throw new SecurityException("Process of extracting SAMLRequest from query string failed: "
                    + queryString);
        }
        appendParameter(builder, queryString, HTTP_POST_PARAM_SAML2_AUTH_REQ);
        // This is optional.
        appendParameter(builder, queryString, RELAY_STATE);
        // This is mandatory, but has already been checked in superclass.
        appendParameter(builder, queryString, SIGNATURE_ALGORITHM);
        return builder.toString();
    }

    /**
     * Append raw query string parameter to the string builder.
     *
     * @param builder     String builder to which to append the parameter.
     * @param queryString The URL query string containing parameters.
     * @param paramName   The name of the parameter to append.
     * @return true       If raw string of parameter is not null.
     */
    private static boolean appendParameter(StringBuilder builder, String queryString,
                                           String paramName) {

        String rawParam = URISupport.getRawQueryStringParameter(queryString, paramName);
        if (StringUtils.isBlank(rawParam)) {
            return false;
        }
        if (builder.length() > 0) {
            builder.append('&');
        }
        builder.append(rawParam);
        return true;
    }
}
