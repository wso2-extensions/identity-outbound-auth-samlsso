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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;

import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.SecurityException;

import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators.LogoutReqSignatureValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.StatusCodes.SUCCESS_CODE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        SP_ENTITY_ID;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        SSO_URL;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        IS_AUTHN_RESP_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        IS_LOGOUT_REQ_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        INCLUDE_CERT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.
        IS_SLO_REQUEST_ACCEPTED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.CERTIFICATE_TYPE;
import static org.wso2.carbon.identity.base.IdentityConstants.TRUE;

/**
 * A Utility which provides functionality to handle federated idp initiated saml logout requests.
 */
public class SAMLLogoutUtil {

    private static final Log log = LogFactory.getLog(SAMLLogoutUtil.class);
    private static boolean isBootStrapped = false;

    private SAMLLogoutUtil() {

    }

    /**
     * Bootstrap the OpenSAML2 library only if it is not bootstrapped.
     *
     * @throws FrameworkException Error when bootstrapping.
     */
    public static void doBootstrap() throws FrameworkException {

        if (!isBootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                isBootStrapped = true;
            } catch (ConfigurationException e) {
                throw new FrameworkException("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }

    /**
     * Build status of the logout response.
     *
     * @param responseStatusCode Status code of the response.
     * @param responseStatusMsg  Status message of the response.
     * @return Status object of Status element.
     */
    private static Status buildStatus(String responseStatusCode, String responseStatusMsg) {

        Status status = new StatusBuilder().buildObject();

        // Set the status code.
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(responseStatusCode);
        status.setStatusCode(statusCode);

        // Set the status Message.
        if (StringUtils.isNotBlank(responseStatusMsg)) {
            StatusMessage stateMesssage = new StatusMessageBuilder().buildObject();
            stateMesssage.setMessage(responseStatusMsg);
            status.setStatusMessage(stateMesssage);
        }
        return status;
    }

    /**
     * Generate a unique ID for logout response.
     *
     * @return Generated unique ID.
     */
    private static String createID() throws IdentityException {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityException("Error while generating Secure Random ID", e);
        }
    }

    /**
     * Extract the required federated identity provider's configurations into a map.
     *
     * @param identityProvider {@link IdentityProvider}Federated identity provider.
     * @return Map<String, String> Map of properties of the Identity Provider.
     */
    public static Map<String, String> getFederatedIdPConfigs(IdentityProvider identityProvider) {

        Property[] properties = identityProvider.getDefaultAuthenticatorConfig().getProperties();
        List<String> idpPropertyNames = Arrays.asList(SP_ENTITY_ID, SSO_URL, IS_AUTHN_RESP_SIGNED,
                INCLUDE_CERT, IS_LOGOUT_REQ_SIGNED, IS_SLO_REQUEST_ACCEPTED);

        return Arrays.stream(properties)
                .filter(t -> idpPropertyNames.contains(t.getName()))
                .collect(Collectors.toMap(Property::getName, Property::getValue));
    }

    /**
     * Build error response when request contain validation or processing errors.
     *
     * @param samlMessageContext {@link SAMLMessageContext} object which holds details on logout flow.
     * @param inResponseTo       ID of the Logout Request.
     * @param statusCode         Status Code of the Error Response.
     * @param statusMsg          Status Message of the Error Response.
     * @return String            Encoded Error Response.
     * @throws SAMLIdentityException Error when building the Error Response.
     */
    public static String buildErrorResponse(SAMLMessageContext samlMessageContext, String
            inResponseTo, String statusCode, String statusMsg) throws SAMLIdentityException {

        try {
            LogoutResponse errorResponse = buildResponse(samlMessageContext, inResponseTo, statusCode, statusMsg);
            return SSOUtils.encode(SSOUtils.marshall(errorResponse));
        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error Serializing the SAML Response", e);
        }
    }

    /**
     * Build the Logout Response for logout request from the federated IdP.
     *
     * @param samlMessageContext {@link SAMLMessageContext} object which holds details on logout flow.
     * @param inResponseTo       ID of the Logout Request.
     * @param statusCode         Status Code of the Error Response.
     * @param statusMsg          Status Message of the Error Response.
     * @return Logout Response   Built Logout Response.
     * @throws SAMLIdentityException Error when building the Logout Response.
     */
    public static LogoutResponse buildResponse(SAMLMessageContext samlMessageContext, String inResponseTo,
                                               String statusCode, String statusMsg) throws SAMLIdentityException {

        try {
            doBootstrap();
            String issuerID = (String) samlMessageContext.getFedIdPConfigs().get(SP_ENTITY_ID);
            String acsUrl = (String) samlMessageContext.getFedIdPConfigs().get(SSO_URL);
            String isResponseSigned = (String) samlMessageContext.getFedIdPConfigs().get(IS_AUTHN_RESP_SIGNED);
            boolean isIncludeCert = TRUE.equals(samlMessageContext.getFedIdPConfigs().get(INCLUDE_CERT));

            LogoutResponse logoutResp = new LogoutResponseBuilder().buildObject();
            logoutResp.setID(createID());
            logoutResp.setInResponseTo(inResponseTo);
            logoutResp.setIssuer(getIssuer(issuerID));
            logoutResp.setVersion(SAMLVersion.VERSION_20);
            logoutResp.setStatus(buildStatus(statusCode, statusMsg));
            logoutResp.setIssueInstant(new DateTime());
            logoutResp.setDestination(acsUrl);

            if (TRUE.equals(isResponseSigned) && SUCCESS_CODE.equals(statusCode)) {
                SSOUtils.setSignature(logoutResp, null, null, isIncludeCert,
                        new X509CredentialImpl(samlMessageContext.getTenantDomain(), null));
            }
            return logoutResp;

        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error occurred while setting the signature of logout response", e);
        } catch (FrameworkException e) {
            throw new SAMLIdentityException("Error in bootstrapping the OpenSAML2 library", e);
        } catch (IdentityException e) {
            throw new SAMLIdentityException("Error while building Secure Random ID for the logout response", e);
        }
    }

    /**
     * Build the issuer for the logout response.
     *
     * @param issuerID Index of the issuer in the SAML Logout Request.
     * @return Built issuer object for Logout Response.
     */
    private static Issuer getIssuer(String issuerID) {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerID);
        return issuer;
    }

    /**
     * Validate the signature of the LogoutRequest against the given certificate.
     *
     * @param logoutRequest {@link LogoutRequest}object to be validated.
     * @return true           If signature of the Logout Request is valid.
     * @throws SAMLIdentityException Error when validating the signature.
     */
    public static boolean isValidSignature(LogoutRequest logoutRequest, SAMLMessageContext
            samlMessageContext) throws SAMLIdentityException {

        String issuer = logoutRequest.getIssuer().getValue();
        X509Certificate x509Certificate = generateX509Certificate(samlMessageContext.
                getFederatedIdP().getCertificate());

        LogoutReqSignatureValidator signatureValidator = new LogoutReqSignatureValidator();
        try {
            if (samlMessageContext.getSAMLLogoutRequest().isPost()) {
                return signatureValidator.validateXMLSignature(logoutRequest, (X509Credential) x509Certificate, null);
            } else {
                return signatureValidator.validateSignature(samlMessageContext.getSAMLLogoutRequest().getQueryString(),
                        issuer, x509Certificate);
            }
        } catch (SecurityException | IdentityException e) {
            throw new SAMLIdentityException ("Process of validating the signature failed for the logout request with" +
                    "issuer: " + logoutRequest.getIssuer().getValue(), e);
        }
    }

    /**
     * Generate the X509Certificate using the certificate string value in the identity provider's configuration.
     *
     * @param certificate String value of the certificate in the IdP's configurations.
     * @throws SAMLIdentityException Error while generating the X509Certificate.
     */
    private static X509Certificate generateX509Certificate(String certificate)
            throws SAMLIdentityException {

        byte[] certificateData = java.util.Base64.getDecoder().decode(certificate);
        try {
            return (java.security.cert.X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).
                    generateCertificate(new ByteArrayInputStream(certificateData));
        } catch (CertificateException e) {
            throw new SAMLIdentityException("Error occurred while generating X509Certificate using the " +
                    "string value of the certificate in IdP's properties: " + certificate, e);
        }
    }

    /**
     * @param logoutRequest {@link LogoutRequest} object.
     * @return String               Session Index of the Logout Request.
     * @throws SAMLIdentityException Error while extracting the Session Index.
     */
    public static String getSessionIndex(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (CollectionUtils.isNotEmpty(logoutRequest.getSessionIndexes())) {
            if (StringUtils.isNotBlank(logoutRequest.getSessionIndexes().get(0).getSessionIndex())) {
                return logoutRequest.getSessionIndexes().get(0).getSessionIndex();
            }
        }
        String notification = "Could not extract the session index from the logout request";
        if (log.isDebugEnabled()) {
            log.debug(notification);
        }
        throw new SAMLIdentityException(notification);
    }
}
