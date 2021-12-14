/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeImpl;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAMLSSOAuthenticator;
import org.wso2.carbon.identity.application.authenticator.samlsso.artifact.SAMLSSOArtifactResolutionService;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.CertificateInfo;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.opensaml.saml.saml2.core.StatusCode.SUCCESS;
import static org.wso2.carbon.CarbonConstants.AUDIT_LOG;

public class DefaultSAML2SSOManager implements SAML2SSOManager {

    private static final String SIGN_AUTH2_SAML_USING_SUPER_TENANT = "SignAuth2SAMLUsingSuperTenant";
    private static final String NAME_ID_TYPE = "NameIDType";
    private static final Log log = LogFactory.getLog(DefaultSAML2SSOManager.class);
    private static boolean bootStrapped = false;
    private static String DEFAULT_MULTI_ATTRIBUTE_SEPARATOR = ",";
    private static String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private static final String VERIFY_ASSERTION_ISSUER = "VerifyAssertionIssuer";
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    private IdentityProvider identityProvider = null;
    private Map<String, String> properties;
    private String tenantDomain;

    public static void doBootstrap() {

        /* Initializing the OpenSAML library */
        if (!bootStrapped) {
            Thread thread = Thread.currentThread();
            ClassLoader loader = thread.getContextClassLoader();
            thread.setContextClassLoader(new DefaultSAML2SSOManager().getClass().getClassLoader());
            try {
                SAMLInitializer.doBootstrap();
                bootStrapped = true;
            } catch (InitializationException e) {
                log.error("Error in bootstrapping the OpenSAML3 library", e);
            } finally {
                thread.setContextClassLoader(loader);
            }
        }

    }

    @Override
    public void init(String tenantDomain, Map<String, String> properties, IdentityProvider idp)
            throws SAMLSSOException {

        this.tenantDomain = tenantDomain;
        this.identityProvider = idp;
        this.properties = properties;
    }

    /**
     * Returns the redirection URL with the appended SAML2
     * Request message
     *
     * @param request SAML 2 request
     * @return redirectionUrl
     */
    @Override
    public String buildRequest(HttpServletRequest request, boolean isLogout, boolean isPassive,
                               String loginPage, AuthenticationContext context)
            throws SAMLSSOException {

        doBootstrap();
        String contextIdentifier = context.getContextIdentifier();
        RequestAbstractType requestMessage;

        if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) == null) {
            String queryParam = context.getQueryParams();
            if (queryParam != null) {
                String[] params = queryParam.split("&");
                for (String param : params) {
                    String[] values = param.split("=");
                    if (values.length == 2 && SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ.equals(values[0])) {
                        request.setAttribute(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ, values[1]);
                        break;
                    }
                }
            }
        }

        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);
            String nameIdFormat = (String) request.getSession().getAttribute(SSOConstants.NAME_ID_FORMAT);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier,
                    nameIdFormat, context);
        }
        String idpUrl = null;
        boolean isSignAuth2SAMLUsingSuperTenant = false;

        String encodedRequestMessage = encodeRequestMessage(requestMessage);
        StringBuilder httpQueryString = new StringBuilder("SAMLRequest=" + encodedRequestMessage);

        try {
            httpQueryString.append("&RelayState=" + URLEncoder.encode(contextIdentifier, "UTF-8").trim());
        } catch (UnsupportedEncodingException e) {
            throw new SAMLSSOException(ErrorMessages.URL_ENCODING_RELAY_STATE.getCode(),
                    ErrorMessages.URL_ENCODING_RELAY_STATE.getMessage(), e);
        }

        boolean isRequestSigned;
        if (!isLogout) {
            isRequestSigned = SSOUtils.isAuthnRequestSigned(properties);
        } else {
            isRequestSigned = SSOUtils.isLogoutRequestSigned(properties);
        }

        if (isRequestSigned) {
            String signatureAlgoProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
            if (StringUtils.isEmpty(signatureAlgoProp)) {
                signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
            }
            String signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms()
                    .get(signatureAlgoProp);

            Map<String, String> parameterMap = FileBasedConfigurationBuilder.getInstance()
                    .getAuthenticatorBean(SSOConstants.AUTHENTICATOR_NAME).getParameterMap();
            if (parameterMap.size() > 0) {
                isSignAuth2SAMLUsingSuperTenant = Boolean.parseBoolean(parameterMap.
                        get(SIGN_AUTH2_SAML_USING_SUPER_TENANT));
            }
            if (isSignAuth2SAMLUsingSuperTenant) {
                SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                        new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null));
            } else {
                SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }
        if (loginPage.indexOf("?") > -1) {
            idpUrl = loginPage.concat("&").concat(httpQueryString.toString());
        } else {
            idpUrl = loginPage.concat("?").concat(httpQueryString.toString());
        }
        return idpUrl;
    }

    /**
     * @param request
     * @param isLogout
     * @param isPassive
     * @param loginPage
     * @return return encoded SAML Auth request
     * @throws SAMLSSOException
     */
    public String buildPostRequest(HttpServletRequest request, boolean isLogout,
                                   boolean isPassive, String loginPage, AuthenticationContext context) throws SAMLSSOException {

        doBootstrap();
        RequestAbstractType requestMessage;
        String signatureAlgoProp = null;
        String digestAlgoProp = null;
        String includeCertProp = null;
        String signatureAlgo = null;
        String digestAlgo = null;
        boolean includeCert = false;

        // get Signature Algorithm
        signatureAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(signatureAlgoProp)) {
            signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
        }
        signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(signatureAlgoProp);

        // get Digest Algorithm
        digestAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        if (StringUtils.isEmpty(digestAlgoProp)) {
            digestAlgoProp = IdentityApplicationConstants.XML.DigestAlgorithm.SHA1;
        }
        digestAlgo = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(digestAlgoProp);

        includeCertProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT);
        if (StringUtils.isEmpty(includeCertProp) || Boolean.parseBoolean(includeCertProp)) {
            includeCert = true;
        }

        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
            if (SSOUtils.isAuthnRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);
            String nameIdFormat = (String) request.getSession().getAttribute(SSOConstants.NAME_ID_FORMAT);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier,
                    nameIdFormat, context);
            if (SSOUtils.isLogoutRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }

        return SSOUtils.encode(SSOUtils.marshall(requestMessage));
    }

    @Override
    public void processResponse(HttpServletRequest request) throws SAMLSSOException {

        doBootstrap();
        if (isSAMLArtifactResponse(request)) {
            processArtifactResponse(request);
        } else {
            processSAMLResponse(request);
        }
    }

    private void processArtifactResponse(HttpServletRequest request) throws SAMLSSOException {

        SAMLSSOArtifactResolutionService artifactResolutionService = new SAMLSSOArtifactResolutionService(properties,
                tenantDomain);
        try {
            ArtifactResponse artifactResponse = artifactResolutionService.getSAMLArtifactResponse(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_ARTIFACT_ID));
            validateSignature(artifactResponse);

            String code;
            for (XMLObject child : artifactResponse.getOrderedChildren()) {
                if (child instanceof Response || child instanceof LogoutResponse) {
                    validateResponseFormat(child);

                    for (XMLObject responseElement : child.getOrderedChildren()) {
                        if (responseElement instanceof Status) {
                            for (XMLObject statusElement : responseElement.getOrderedChildren()) {
                                code = getStatusCode(statusElement);
                                if (SUCCESS.equals(code)) {
                                    executeSAMLReponse(request, child);
                                } else {
                                    throw new SAMLSSOException(
                                            ErrorMessages.SAML_RESPONSE_STATUS_CODE_MISMATCHED_WITH_SUCCESS_CODE
                                                    .getCode(),
                                            ErrorMessages.SAML_RESPONSE_STATUS_CODE_MISMATCHED_WITH_SUCCESS_CODE
                                                    .getMessage());
                                }
                            }
                        }
                    }
                }
            }
        } catch (ArtifactResolutionException e) {
            throw new SAMLSSOException(ErrorMessages.ARTIFACT_RESPONSE_RESOLUTION_FAILED.getCode(),
                    ErrorMessages.ARTIFACT_RESPONSE_RESOLUTION_FAILED.getMessage(), e);
        }
    }

    private void processSAMLResponse(HttpServletRequest request) throws SAMLSSOException {

        String decodedResponse = new String(org.apache.commons.codec.binary.Base64.decodeBase64(request.getParameter(
                SSOConstants.HTTP_POST_PARAM_SAML2_RESP).getBytes()));
        XMLObject samlObject = SSOUtils.unmarshall(decodedResponse);
        validateResponseFormat(samlObject);
        executeSAMLReponse(request, samlObject);
    }

    private void executeSAMLReponse(HttpServletRequest request, XMLObject samlObject) throws SAMLSSOException {
        if (samlObject instanceof LogoutResponse) {
            //This is a SAML response for a single logout request from the SP
            // TODO need to change the API of this method to prevent unmarshalling twice.
            doSLO(request);
        } else if (samlObject instanceof Response) {
            processSSOResponse(request, (Response) samlObject);
        } else {
            throw new SAMLSSOException(ErrorMessages.UNABLE_TO_PROCESS_SAML_OBJECT_TYPE.getCode(),
                    ErrorMessages.UNABLE_TO_PROCESS_SAML_OBJECT_TYPE.getMessage());
        }
    }

    private String getStatusCode(XMLObject statusCode) {

        String code;
        if (statusCode.hasChildren()) {
            code = ((StatusCodeImpl) statusCode.getOrderedChildren().get(0)).getValue();
        } else {
            code = ((StatusCode) statusCode).getValue();
        }
        return code;
    }

    private boolean isSAMLArtifactResponse(HttpServletRequest request) {

        return request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_ARTIFACT_ID) != null;
    }

    protected AuthnRequest getAuthnRequest(AuthenticationContext context) throws SAMLSSOException {

        AuthnRequest authnRequest = null;
        AuthenticationRequest authenticationRequest = context.getAuthenticationRequest();
        String[] samlRequestParams = authenticationRequest
                .getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
        String samlRequest = null;
        if (samlRequestParams != null && samlRequestParams.length > 0) {
            samlRequest = samlRequestParams[0];
            XMLObject xmlObject;
            if (authenticationRequest.isPost()) {
                xmlObject = SSOUtils.unmarshall(SSOUtils.decodeForPost(samlRequest));
            } else {
                xmlObject = SSOUtils.unmarshall(SSOUtils.decode(samlRequest));
            }
            validateResponseFormat(xmlObject);
            if (xmlObject instanceof AuthnRequest) {
                authnRequest = (AuthnRequest) xmlObject;
            }
        }
        return authnRequest;
    }

    protected Extensions getSAMLExtensions(HttpServletRequest request) {

        try {
            String samlRequest = request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
            if (samlRequest == null) {
                samlRequest = (String) request.getAttribute(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
            }

            if (samlRequest != null) {
                XMLObject xmlObject;
                if (SSOConstants.HTTP_POST.equals(request.getMethod())) {
                    xmlObject = SSOUtils.unmarshall(SSOUtils.decodeForPost(samlRequest));
                } else {
                    xmlObject = SSOUtils.unmarshall(SSOUtils.decode(samlRequest));
                }
                validateResponseFormat(xmlObject);
                if (xmlObject instanceof AuthnRequest) {
                    AuthnRequest authnRequest = (AuthnRequest) xmlObject;
                    Extensions oldExtensions = authnRequest.getExtensions();
                    if (oldExtensions != null) {
                        ExtensionsBuilder extBuilder = new ExtensionsBuilder();
                        Extensions extensions = extBuilder.buildObject(SAMLConstants.SAML20P_NS,
                                Extensions.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20P_PREFIX);
                        extensions.setDOM(oldExtensions.getDOM());
                        return extensions;
                    }
                }
            }
        } catch (Exception e) { // TODO IDENTITY-2421
            //ignore
            log.debug("Error while loading SAML Extensions", e);
        }

        return null;
    }

    protected Extensions getSAMLExtensions(AuthnRequest inboundAuthnRequest) {

        Extensions extensions = null;
        Extensions oldExtensions = inboundAuthnRequest.getExtensions();
        if (oldExtensions != null) {
            ExtensionsBuilder extBuilder = new ExtensionsBuilder();
            extensions = extBuilder.buildObject(SAMLConstants.SAML20P_NS,
                    Extensions.DEFAULT_ELEMENT_LOCAL_NAME, SAMLConstants.SAML20P_PREFIX);
            extensions.setDOM(oldExtensions.getDOM());
        }
        return extensions;
    }

    /**
     * This method handles the logout requests from the IdP
     * Any request for the defined logout URL is handled here
     *
     * @param request
     */
    public void doSLO(HttpServletRequest request) throws SAMLSSOException {

        doBootstrap();
        XMLObject samlObject = null;
        if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) != null) {
            samlObject = SSOUtils.unmarshall(new String(Base64.decodeBase64(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ).getBytes())));
        }
        if (samlObject == null) {
            samlObject = SSOUtils.unmarshall(new String(Base64.decodeBase64(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_RESP).getBytes())));
        }
        validateResponseFormat(samlObject);
        if (samlObject instanceof LogoutRequest) {
            LogoutRequest logoutRequest = (LogoutRequest) samlObject;
            String sessionIndex = logoutRequest.getSessionIndexes().get(0).getSessionIndex();
        } else if (samlObject instanceof LogoutResponse) {
            request.getSession().invalidate();
        } else {
            throw new SAMLSSOException(ErrorMessages.INVALID_SINGLE_LOGOUT_SAML_REQUEST.getCode(),
                    ErrorMessages.INVALID_SINGLE_LOGOUT_SAML_REQUEST.getMessage());
        }
    }

    private void processSSOResponse(HttpServletRequest request, Response samlResponse) throws SAMLSSOException {

        Assertion assertion = null;

        if (SSOUtils.isAssertionEncryptionEnabled(properties)) {
            List<EncryptedAssertion> encryptedAssertions = samlResponse.getEncryptedAssertions();
            EncryptedAssertion encryptedAssertion = null;
            if (isNotEmpty(encryptedAssertions)) {
                encryptedAssertion = encryptedAssertions.get(0);
                try {
                    assertion = getDecryptedAssertion(encryptedAssertion);
                } catch (Exception e) {
                    throw new SAMLSSOException(ErrorMessages.UNABLE_TO_DECRYPT_THE_SAML_ASSERTION.getCode(),
                            ErrorMessages.UNABLE_TO_DECRYPT_THE_SAML_ASSERTION.getMessage(), e);
                }
            }
        } else {
            List<Assertion> assertions = samlResponse.getAssertions();
            if (isNotEmpty(assertions)) {
                assertion = assertions.get(0);
            }
        }

        if (assertion == null) {
            if (samlResponse.getStatus() != null && samlResponse.getStatus().getStatusCode() != null) {
                if (samlResponse.getStatus().getStatusCode().getValue().equals(
                        SSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR)) {
                    if (samlResponse.getStatus().getStatusCode().getStatusCode() != null) {
                        if (samlResponse.getStatus().getStatusCode().getStatusCode().getValue().equals(
                                SSOConstants.StatusCodes.NO_PASSIVE)) {
                            return;
                        } else if (log.isDebugEnabled()) {
                            log.debug("SAML Response status code object value is: " +
                                    samlResponse.getStatus().getStatusCode().getStatusCode().getValue()
                                    + ".");
                            throw new SAMLSSOException("SAML Response status code object value is not" +
                                    "equal to: " + SSOConstants.StatusCodes.NO_PASSIVE + ".");
                        }
                    } else if (log.isDebugEnabled()) {
                        log.debug("SAML Response status code object is null.");
                    }
                } else if (log.isDebugEnabled()) {
                    log.debug("SAML Response status code value is: " +
                            samlResponse.getStatus().getStatusCode().getValue() + ".");
                    throw new SAMLSSOException("SAML Response status code value is not equal to: " +
                            SSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR + ".");
                }
            } else if (log.isDebugEnabled()) {
                log.debug("SAML Response status or the status code is null.");
            }

            throw new SAMLSSOException(ErrorMessages.SAML_ASSERTION_NOT_FOUND_IN_RESPONSE.getCode(),
                    ErrorMessages.SAML_ASSERTION_NOT_FOUND_IN_RESPONSE.getMessage());
        }

        // Validate the assertion issuer. This is an optional validation which is not mandate by the spec.
        validateAssertionIssuer(assertion);

        // validate the assertion validity period
        validateAssertionValidityPeriod(assertion);
        
        // this request attribute is populated in processAuthenticationResponse of SAMLSSOAuthenticator
        AuthenticationContext context = (AuthenticationContext) request
                .getAttribute(SAMLSSOAuthenticator.AUTHENTICATION_CONTEXT);

        // validate audience restriction
        validateAudienceRestriction(assertion, getIssuer(context));
        
        // validate signature this SP only looking for assertion signature
        validateSignature(samlResponse, assertion);

        // Get the subject name from the Response Object and forward it to login_action.jsp
        String subject = null;
        String nameQualifier = null;
        String spNameQualifier = null;
        String nameIdFormat = null;
        if (assertion.getSubject() != null && assertion.getSubject().getNameID() != null) {
            subject = assertion.getSubject().getNameID().getValue();
        }

        if (subject == null) {
            throw new SAMLSSOException(ErrorMessages.SUBJECT_NAME_NOT_FOUND_IN_RESPONSE.getCode(),
                    ErrorMessages.SUBJECT_NAME_NOT_FOUND_IN_RESPONSE.getMessage());
        }

        request.getSession().setAttribute("username", subject); // get the subject
        nameQualifier = assertion.getSubject().getNameID().getNameQualifier();
        spNameQualifier = assertion.getSubject().getNameID().getSPNameQualifier();
        nameIdFormat = assertion.getSubject().getNameID().getFormat();

        request.getSession(false).setAttribute("samlssoAttributes", getAssertionStatements(assertion));

        if (assertion.getAuthnStatements() != null) {
            List<String> authnContextClassRefs = new ArrayList<>();
            for (AuthnStatement authnStatement : assertion.getAuthnStatements()) {
                if (authnStatement.getAuthnContext() != null
                        && authnStatement.getAuthnContext().getAuthnContextClassRef() != null
                        && StringUtils.isNotBlank(authnStatement.getAuthnContext().getAuthnContextClassRef()
                        .getAuthnContextClassRef())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Received AuthnContextClassRef: " + authnStatement.getAuthnContext()
                                .getAuthnContextClassRef().getAuthnContextClassRef());
                    }
                    authnContextClassRefs.add(authnStatement.getAuthnContext().getAuthnContextClassRef()
                            .getAuthnContextClassRef());
                }
            }

            if (!authnContextClassRefs.isEmpty()) {
                Map<String, Object> authnContextClassRefMap = new HashMap<>();
                authnContextClassRefMap.put(SSOConstants.AUTHN_CONTEXT_CLASS_REF, authnContextClassRefs);
                authnContextClassRefMap.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID,
                        assertion.getIssuer().getValue());
                request.getSession().setAttribute(SSOConstants.AUTHN_CONTEXT_CLASS_REF, authnContextClassRefMap);
            }
        }

        //For removing the session when the single sign out request made by the SP itself
        if (SSOUtils.isLogoutEnabled(properties)) {
            String sessionId = assertion.getAuthnStatements().get(0).getSessionIndex();
            if (sessionId == null) {
                throw new SAMLSSOException(ErrorMessages.IDP_SESSION_ID_NOT_FOUND_FOR_SLO.getCode(),
                        ErrorMessages.IDP_SESSION_ID_NOT_FOUND_FOR_SLO.getMessage());
            }
            request.getSession().setAttribute(SSOConstants.IDP_SESSION, sessionId);
            request.getSession().setAttribute(SSOConstants.NAME_QUALIFIER, nameQualifier);
            request.getSession().setAttribute(SSOConstants.SP_NAME_QUALIFIER, spNameQualifier);
            request.getSession().setAttribute(SSOConstants.NAME_ID_FORMAT, nameIdFormat);
        }

    }

    /**
     * this method builds the SAML logout request corresponding to the federated identity provider.
     * override this method to customize the SAML request.
     * 
     * @param user
     * @param sessionIndexStr
     * @param idpUrl
     * @param nameQualifier
     * @param spNameQualifier
     * @param nameIdFormat
     * @param context
     * @return
     * @throws SAMLSSOException
     */
    protected LogoutRequest buildLogoutRequest(String user, String sessionIndexStr, String idpUrl, String nameQualifier,
            String spNameQualifier, String nameIdFormat, AuthenticationContext context) throws SAMLSSOException {

        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();

        logoutReq.setID(SSOUtils.createID());
        logoutReq.setDestination(idpUrl);

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();

        String spEntityId = getIssuer(context);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();

        if (StringUtils.isNotBlank(nameIdFormat)) {
            nameId.setFormat(nameIdFormat);
        } else {
            String includeNameIDPolicyProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);
            if (StringUtils.isBlank(includeNameIDPolicyProp) || Boolean.parseBoolean(includeNameIDPolicyProp)) {
                nameId.setFormat(NameIDType.UNSPECIFIED);
            }
        }

        nameId.setValue(user);
        nameId.setNameQualifier(nameQualifier);
        nameId.setSPNameQualifier(spNameQualifier);
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();

        if (sessionIndexStr != null) {
            sessionIndex.setSessionIndex(sessionIndexStr);
        } else {
            sessionIndex.setSessionIndex(UUID.randomUUID().toString());
        }

        logoutReq.getSessionIndexes().add(sessionIndex);
        logoutReq.setReason("Single Logout");

        return logoutReq;
    }

    /**
     * this method builds the SAML request corresponding to the federated identity provider.
     * override this method to customize the SAML request.
     * 
     * @param request
     * @param isPassive
     * @param idpUrl
     * @param context
     * @return
     * @throws SAMLSSOException
     */
    protected AuthnRequest buildAuthnRequest(HttpServletRequest request, boolean isPassive, String idpUrl,
            AuthenticationContext context) throws SAMLSSOException {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");

        String spEntityId = getIssuer(context);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        DateTime issueInstant = new DateTime();

        /* Creation of AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");
        authRequest.setForceAuthn(isForceAuthenticate(context));
        authRequest.setIsPassive(isPassive);
        authRequest.setIssueInstant(issueInstant);

        String includeProtocolBindingProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
        if (StringUtils.isEmpty(includeProtocolBindingProp) || Boolean.parseBoolean(includeProtocolBindingProp)) {
            authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        }

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                        .get(SSOConstants.AUTHENTICATOR_NAME);

        String acsUrl = getAcsUrl(authenticatorConfig);
        authRequest.setAssertionConsumerServiceURL(acsUrl);
        authRequest.setIssuer(issuer);
        authRequest.setID(SSOUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(idpUrl);

        String attributeConsumingServiceIndexProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        if (StringUtils.isNotEmpty(attributeConsumingServiceIndexProp)) {
            try {
                authRequest.setAttributeConsumingServiceIndex(Integer
                        .valueOf(attributeConsumingServiceIndexProp));
            } catch (NumberFormatException e) {
                log.error(
                        "Error while populating SAMLRequest with AttributeConsumingServiceIndex: "
                                + attributeConsumingServiceIndexProp, e);
            }
        }

        String includeNameIDPolicyProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);

        boolean isNameIDPolicyPropIncluded;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(
                IdentityConstants.ServerConfig.ADD_NAME_ID_POLICY_IF_UNSPECIFIED))) {
            // Adding empty string check for backward compatibility.
            isNameIDPolicyPropIncluded = StringUtils.isEmpty(includeNameIDPolicyProp) ||
                    Boolean.parseBoolean(includeNameIDPolicyProp);
        } else {
            isNameIDPolicyPropIncluded = Boolean.parseBoolean(includeNameIDPolicyProp);
        }

        if (isNameIDPolicyPropIncluded) {
            NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
            NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();

            String nameIdType = properties.get(NAME_ID_TYPE);
            if (StringUtils.isBlank(nameIdType)) {
                // NameID format was not set from the UI. Check the application-authentication.xml configs
                if (authenticatorConfig != null) {
                    nameIdType = authenticatorConfig.getParameterMap().get(NAME_ID_TYPE);
                    if (StringUtils.isBlank(nameIdType)) {
                        // No NameID format set. Let's go with the default NameID format
                        nameIdType = NameIDType.UNSPECIFIED;
                    }
                }
            }
            nameIdPolicy.setFormat(nameIdType);
            if (spEntityId != null && !spEntityId.isEmpty()) {
                nameIdPolicy.setSPNameQualifier(spEntityId);
            }
            //nameIdPolicy.setSPNameQualifier(issuer);
            nameIdPolicy.setAllowCreate(true);
            authRequest.setNameIDPolicy(nameIdPolicy);
        }

        //Get the inbound SAMLRequest
        AuthnRequest inboundAuthnRequest = getAuthnRequest(context);

        RequestedAuthnContext requestedAuthnContext = buildRequestedAuthnContext(inboundAuthnRequest);
        if (requestedAuthnContext != null) {
            authRequest.setRequestedAuthnContext(requestedAuthnContext);
        }

        Extensions extensions = getSAMLExtensions(request);
        if (extensions != null) {
            authRequest.setExtensions(extensions);
        }

        return authRequest;
    }

    private String getAcsUrl(AuthenticatorConfig authenticatorConfig) throws SAMLSSOException {

        String acsUrl = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.ACS_URL);

        if (StringUtils.isNotEmpty(acsUrl) && log.isDebugEnabled()) {
            log.debug("Picking SAML acs URL from " + identityProvider.getIdentityProviderName() + " IDP's "
                    + "configuration: " + acsUrl);
        }

        if (StringUtils.isEmpty(acsUrl) && authenticatorConfig != null) {
            String tmpAcsUrl = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.SAML_SSO_ACS_URL);
            if (StringUtils.isNotBlank(tmpAcsUrl)) {
                acsUrl = tmpAcsUrl;
                if (log.isDebugEnabled()) {
                    log.debug("Picking SAML acs URL from application-authentication.xml: " + acsUrl);
                }
            }
        }

        if (StringUtils.isEmpty(acsUrl)) {
            try {
                acsUrl = ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build()
                        .getAbsolutePublicURL();
            } catch (URLBuilderException e) {
                throw new SAMLSSOException("Error while building the acs url.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Falling back to default SAML acs URL of the server: " + acsUrl);
            }
        }

        return acsUrl;
    }

    protected RequestedAuthnContext buildRequestedAuthnContext(AuthnRequest inboundAuthnRequest) throws SAMLSSOException {

        /* AuthnContext */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = null;
        RequestedAuthnContext requestedAuthnContext = null;

        String includeAuthnContext = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);

        if (StringUtils.isNotEmpty(includeAuthnContext) && "as_request".equalsIgnoreCase(includeAuthnContext)) {
            if (inboundAuthnRequest != null) {
                RequestedAuthnContext incomingRequestedAuthnContext = inboundAuthnRequest.getRequestedAuthnContext();
                if (incomingRequestedAuthnContext != null) {
                    requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
                    requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
                    requestedAuthnContext.setDOM(incomingRequestedAuthnContext.getDOM());
                }
            }
        } else if (StringUtils.isEmpty(includeAuthnContext) || "yes".equalsIgnoreCase(includeAuthnContext)) {
            requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
            requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
            /* AuthnContextClass */
            AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();

            String authnContextClass = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_CLASS);

            if (StringUtils.isNotBlank(authnContextClass)) {
                String[] authnContextClassList = authnContextClass.split(DEFAULT_MULTI_ATTRIBUTE_SEPARATOR);
                for (String authnContextClassListElement : authnContextClassList) {
                    AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                            .buildObject(SAMLConstants.SAML20_NS,
                                    AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                    SAMLConstants.SAML20_PREFIX);
                    String samlAuthnContextURN;
                    if (authnContextClassListElement.equals(IdentityApplicationConstants.Authenticator.SAML2SSO
                            .CUSTOM_AUTHENTICATION_CONTEXT_CLASS_OPTION)) {
                        samlAuthnContextURN = properties.get(IdentityApplicationConstants.Authenticator
                                .SAML2SSO.ATTRIBUTE_CUSTOM_AUTHENTICATION_CONTEXT_CLASS);
                    } else{
                        samlAuthnContextURN = IdentityApplicationManagementUtil
                                .getSAMLAuthnContextClasses().get(authnContextClassListElement);
                    }

                    if (StringUtils.isNotBlank(samlAuthnContextURN)) {
                        // There was one matched URN for given authnContextClass.
                        authnContextClassRef.setAuthnContextClassRef(samlAuthnContextURN);
                    } else {
                        // There are no any matched URN for given authnContextClass, so added authnContextClassListElement name to the
                        // AuthnContextClassRef.
                        authnContextClassRef.setAuthnContextClassRef(authnContextClassListElement);
                    }
                    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
                }

            } else {
                AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                        .buildObject(SAMLConstants.SAML20_NS,
                                AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                                SAMLConstants.SAML20_PREFIX);
                authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
                requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
            }

            /* Authentication Context Comparison Level */
            String authnContextComparison = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);

            if (StringUtils.isNotEmpty(authnContextComparison)) {
                if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
                }
            } else {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            }
        }
        return requestedAuthnContext;
    }

    protected boolean isForceAuthenticate(AuthenticationContext context) {

        boolean forceAuthenticate = false;
        String forceAuthenticateProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
        if ("yes".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = true;
        } else if ("as_request".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = context.isForceAuthenticate();
        }
        return forceAuthenticate;
    }

    protected String encodeRequestMessage(RequestAbstractType requestMessage)
            throws SAMLSSOException {

        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        try {
            authDOM = marshaller.marshall(requestMessage);

            /* Compress the message */
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
            SerializeSupport.writeNode(authDOM, deflaterOutputStream);
            deflaterOutputStream.close();

            /* Encoding the compressed message */
            String encodedRequestMessage = new String(org.apache.commons.codec.binary.Base64.encodeBase64(byteArrayOutputStream.toByteArray(), false));

            byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.toString();

            // log saml
            if (log.isDebugEnabled()) {
                log.debug("SAML Request  :  " + deflaterOutputStream.toString());
            }

            return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();

        } catch (MarshallingException | IOException e) {
            throw new SAMLSSOException(ErrorMessages.IO_ERROR.getCode(),
                    "Error occurred while encoding SAML request", e);
        }
    }

    /**
     * Validate response format.
     *
     * @param response XMLObject response.
     * @throws SAMLSSOException SAMLSSOException.
     */
    protected void validateResponseFormat(XMLObject response) throws SAMLSSOException {

        // Checking for duplicate samlp:Response. This is done to thwart possible XSW attacks
        NodeList responseList = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20P_NS, "Response");
        if (responseList != null && responseList.getLength() > 0) {
            throw new SAMLSSOException(ErrorMessages.INVALID_SCHEMA_FOR_THE_SAML_2_RESPONSE.getCode(),
                    ErrorMessages.INVALID_SCHEMA_FOR_THE_SAML_2_RESPONSE.getMessage());
        }

        // Checking for multiple Assertions. This is done to thwart possible XSW attacks.
        NodeList assertionList = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion");
        if (assertionList != null && assertionList.getLength() > 1) {
            throw new SAMLSSOException(ErrorMessages.PROCESSING_SAML2_MULTIPLE_ASSERTION_ELEMENT_FOUND.getCode(),
                    ErrorMessages.PROCESSING_SAML2_MULTIPLE_ASSERTION_ELEMENT_FOUND.getMessage());
        }
    }

    /*
     * Process the response and returns the results
     */
    private Map<ClaimMapping, String> getAssertionStatements(Assertion assertion) {

        Map<ClaimMapping, String> results = new HashMap<ClaimMapping, String>();
        String multiAttributeSeparator = DEFAULT_MULTI_ATTRIBUTE_SEPARATOR;

        UserRealm realm;
        try {
            realm = SAMLSSOAuthenticatorServiceDataHolder.getInstance().getRealmService().getTenantUserRealm
                    (MultitenantConstants.SUPER_TENANT_ID);
            UserStoreManager userStoreManager = (UserStoreManager) realm.getUserStoreManager();

            multiAttributeSeparator = userStoreManager.
                    getRealmConfiguration().getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
        } catch (UserStoreException e) {
            log.warn("Error while reading MultiAttributeSeparator valaue from primary user store ", e);
        }

        if (assertion != null) {

            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

            if (attributeStatementList != null) {
                for (AttributeStatement statement : attributeStatementList) {
                    List<Attribute> attributesList = statement.getAttributes();
                    for (Attribute attribute : attributesList) {
                        List<XMLObject> values = attribute.getAttributeValues();
                        String attributesValue = null;
                        if (values != null) {
                            for (int i = 0; i < values.size(); i++) {
                                Element value = attribute.getAttributeValues().get(i).getDOM();
                                String attributeValue = value.getTextContent();
                                if (StringUtils.isBlank(attributesValue)) {
                                    attributesValue = attributeValue;
                                } else {
                                    attributesValue = attributesValue + multiAttributeSeparator + attributeValue;
                                }
                            }
                        }

                        results.put(ClaimMapping.build(attribute.getName(),
                                attribute.getName(), null, false), attributesValue);
                    }
                }
            }
        }
        return results;
    }

    /**
     * Validate the AudienceRestriction of SAML2 Response
     *
     * @param assertion SAML2 Assertion
     * @param issuer Issuer of the SAML2 Assertion
     */
    protected void validateAudienceRestriction(Assertion assertion, String issuer) throws SAMLSSOException {

        if (assertion != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                        if (isNotEmpty(audienceRestriction.getAudiences())) {
                            boolean audienceFound = false;
                            for (Audience audience : audienceRestriction.getAudiences()) {
                                if (issuer != null && issuer.equals(audience.getAudienceURI())) {
                                    audienceFound = true;
                                    break;
                                }
                            }
                            if (!audienceFound) {
                                throw new SAMLSSOException(
                                        ErrorMessages.AUDIENCE_RESTRICTION_VALIDATION_FAILED.getCode(),
                                        ErrorMessages.AUDIENCE_RESTRICTION_VALIDATION_FAILED.getMessage());
                            }
                        } else {
                            throw new SAMLSSOException(
                                    ErrorMessages.AUDIENCES_NOT_FOUND.getCode(),
                                    ErrorMessages.AUDIENCES_NOT_FOUND.getMessage());
                        }
                    }
                } else {
                    throw new SAMLSSOException(ErrorMessages.AUDIENCE_RESTRICTION_NOT_FOUND.getCode(),
                            ErrorMessages.AUDIENCE_RESTRICTION_NOT_FOUND.getMessage());
                }
            } else {
                throw new SAMLSSOException(ErrorMessages.SAML_CONDITIONS_NOT_FOUND.getCode(),
                        ErrorMessages.SAML_CONDITIONS_NOT_FOUND.getMessage());
            }
        }
    }

    /**
     * Validate the signature of a SAML2 Response and Assertion.
     *
     * @param response SAML2 Response.
     * @param assertion SAML2 assertion.
     * @throws SAMLSSOException SAMLSSOException.
     */
    protected void validateSignature(Response response, Assertion assertion) throws
            SAMLSSOException {

        if (SSOUtils.isAuthnResponseSigned(properties)) {

            XMLObject signature = response.getSignature();
            if (signature == null) {
                throw new SAMLSSOException(ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_WHILE_ENABLED.getCode(),
                        ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_WHILE_ENABLED.getMessage());
            } else {
                validateSignature(signature);
            }
        }
        if (SSOUtils.isAssertionSigningEnabled(properties)) {

            XMLObject signature = assertion.getSignature();
            if (assertion.getSignature() == null) {
                throw new SAMLSSOException(
                        ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_IN_SAML_ASSERTION_WHILE_SIGNING_ENABLED.getCode(),
                        ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_IN_SAML_ASSERTION_WHILE_SIGNING_ENABLED.getMessage());
            } else {
                validateSignature(signature);
            }
        }
    }

    /**
     * Validate the signature of a SAML2 Artifact Response
     *
     * @param artifactResponse SAML2 Artifact Response
     * @throws SAMLSSOException
     */
    protected void validateSignature(ArtifactResponse artifactResponse) throws SAMLSSOException {

        if (SSOUtils.isArtifactResponseSigningEnabled(properties)) {

            XMLObject signature = artifactResponse.getSignature();
            if (signature == null) {
                throw new SAMLSSOException(
                        ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_IN_ARTIFACT_RESPONSE_WHILE_ENABLED.getCode(),
                        ErrorMessages.SIGNATURE_ELEMENT_NOT_FOUND_IN_ARTIFACT_RESPONSE_WHILE_ENABLED.getMessage());
            } else {
                validateSignature(signature);
            }
        }
    }

    /**
     * Validates the XML Signature element
     *
     * @param signature XML Signature element
     * @throws SAMLSSOException
     */
    protected void validateSignature(XMLObject signature) throws SAMLSSOException {

        SignatureImpl signImpl = (SignatureImpl) signature;
        CertificateInfo[] certificateInfos;
        boolean isExceptionThrown = false;
        SignatureException validationException = null;
        try {
            SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
            signatureProfileValidator.validate(signImpl);
        } catch (SignatureException ex) {
            String logMsg = ErrorMessages.SIGNATURE_NOT_CONFIRM_TO_SAML_SIGNATURE_PROFILE.getMessage();
            AUDIT_LOG.warn(logMsg);
            throw new SAMLSSOException(ErrorMessages.SIGNATURE_NOT_CONFIRM_TO_SAML_SIGNATURE_PROFILE.getCode(),
                    logMsg, ex);
        }

        if (ArrayUtils.isEmpty(identityProvider.getCertificateInfoArray())) {
            throw new SAMLSSOException(ErrorMessages.SIGNATURE_VALIDATION_FAILED_FOR_SAML_RESPONSE.getCode(),
                    ErrorMessages.SIGNATURE_VALIDATION_FAILED_FOR_SAML_RESPONSE.getMessage(),
                    validationException);
        }

        certificateInfos = identityProvider.getCertificateInfoArray();
        if (log.isDebugEnabled()) {
            log.debug("The number of certificates has been found is: " + certificateInfos.length);
        }
        int index = 0;
        for (CertificateInfo certificateInfo : certificateInfos) {
            String certVal = certificateInfo.getCertValue();
            X509Credential credential = new X509CredentialImpl(tenantDomain, certVal);
            try {
                if (log.isDebugEnabled()) {
                    log.debug("Validating the SAML signature with certificate at index: " + index);
                }
                SignatureValidator.validate(signImpl, credential);
                isExceptionThrown = false;
                break;
            } catch (SignatureException e) {
                isExceptionThrown = true;
                if (validationException == null) {
                    validationException = e;
                } else {
                    validationException.addSuppressed(e);
                }
            }
            index++;
        }
        // If all the certification validation fails, then throw the exception.
        if (isExceptionThrown) {
            throw new SAMLSSOException("Signature validation failed for SAML Response", validationException);
        }
    }

    /**
     * Validates the 'Not Before' and 'Not On Or After' conditions of the SAML Assertion
     *
     * @param assertion SAML Assertion element
     * @throws SAMLSSOException
     */
    protected void validateAssertionValidityPeriod(Assertion assertion) throws SAMLSSOException {

        if (assertion.getConditions() != null) {
            DateTime validFrom = assertion.getConditions().getNotBefore();
            DateTime validTill = assertion.getConditions().getNotOnOrAfter();
            int timeStampSkewInSeconds = IdentityUtil.getClockSkewInSeconds();

            if (validFrom != null && validFrom.minusSeconds(timeStampSkewInSeconds).isAfterNow()) {
                throw new SAMLSSOException(ErrorMessages.NOT_BEFORE_CONDITION_NOT_MET.getCode(),
                        ErrorMessages.NOT_BEFORE_CONDITION_NOT_MET.getMessage());
            }

            if (validTill != null && validTill.plusSeconds(timeStampSkewInSeconds).isBeforeNow()) {
                throw new SAMLSSOException(
                        ErrorMessages.NOT_ON_OR_BEFORE_CONDITION_NOT_MET.getCode(),
                        ErrorMessages.NOT_ON_OR_BEFORE_CONDITION_NOT_MET.getMessage());
            }

            if (validFrom != null && validTill != null && validFrom.isAfter(validTill)) {
                throw new SAMLSSOException(ErrorMessages.NOT_ON_OR_BEFORE_CONDITION_NOT_MET.getCode(),
                        "SAML Assertion Condition 'Not Before' must be less than the value of 'Not On Or After'");
            }
        }
    }

    /**
     * Get Decrypted Assertion.
     *
     * @param encryptedAssertion Encrypted assertion.
     * @return Decrypted assertion.
     * @throws Exception Exception.
     */
    protected Assertion getDecryptedAssertion(EncryptedAssertion encryptedAssertion) throws Exception {

        X509Credential credential = new X509CredentialImpl(tenantDomain, null);
        KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
        EncryptedKey key = getEncryptedKey(encryptedAssertion);
        Decrypter decrypter = new Decrypter(null, keyResolver, null);
        SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
                getEncryptionMethod().getAlgorithm());
        Credential shared = CredentialSupport.getSimpleCredential(dkey);
        decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
        decrypter.setRootInNewDocument(true);
        return decrypter.decrypt(encryptedAssertion);
    }

    /**
     * Validate assertion issuer.
     *
     * @param assertion SAML2 assertion.
     * @throws SAMLSSOException SAMLSSOException.
     */
    protected void validateAssertionIssuer(Assertion assertion) throws SAMLSSOException {

        if (isAssertionIssuerVerificationEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Assertion issuer verification is enabled.");
            }

            String idpEntityId = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
            if (!idpEntityId.equals(assertion.getIssuer().getValue())) {
                log.warn("Issuer value in the assertion is invalid. Expected value is '" + idpEntityId + "'," +
                        " but received value in the assertion is '" + assertion.getIssuer().getValue() + "'.");
                throw new SAMLSSOException(ErrorMessages.INVALID_IDP_ID.getCode(),
                        String.format(ErrorMessages.INVALID_IDP_ID.getMessage(),
                                assertion.getIssuer().getValue()));
            }
        }
    }

    private boolean isAssertionIssuerVerificationEnabled() {

        AuthenticatorConfig authenticatorConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorConfigMap().get(SSOConstants.AUTHENTICATOR_NAME);

        if (authenticatorConfig != null && authenticatorConfig.getParameterMap() != null) {
            String isVerifyAssertionIssuer = authenticatorConfig.getParameterMap().get(VERIFY_ASSERTION_ISSUER);
            if (StringUtils.isNotEmpty(isVerifyAssertionIssuer)) {
                return Boolean.parseBoolean(isVerifyAssertionIssuer);
            }
        }
        return false;
    }
    
    /**
     * finds the issuer of the SAML request. this is used at the time we build the request and also
     * at the time we validate the audience in the SAML response.
     * 
     * @param context
     * @return
     */
    protected String getIssuer(AuthenticationContext context) {
        // this is the issuer from the SAML federated authenticator.
        return properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);
    }

    private EncryptedKey getEncryptedKey(EncryptedAssertion encryptedAssertion) throws Exception {

        List<EncryptedKey> encryptedKeys = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys();
        if (isNotEmpty(encryptedKeys)) {
            if (log.isDebugEnabled()) {
                log.debug("EncryptedKey obtain from the encrypted data element.");
            }
            return encryptedKeys.get(0);
        }
        encryptedKeys = encryptedAssertion.getEncryptedKeys();
        if (isNotEmpty(encryptedKeys)) {
            if (log.isDebugEnabled()) {
                log.debug("EncryptedKey obtained from the Assertion.");
            }
            return encryptedKeys.get(0);
        }
        throw new Exception("Could not obtain the encrypted key from the encrypted assertion.");
    }
}
