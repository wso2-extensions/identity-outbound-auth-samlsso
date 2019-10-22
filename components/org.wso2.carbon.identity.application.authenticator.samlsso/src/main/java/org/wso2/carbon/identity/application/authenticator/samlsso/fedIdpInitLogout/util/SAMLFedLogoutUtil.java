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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.util;

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
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.Validators.LogoutReqSignatureValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.SP_ENTITY_ID;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.SSO_URL;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.IS_AUTHN_RESP_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.INCLUDE_CERT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.IS_LOGOUT_REQ_SIGNED;

/**
 * A Utility which provides functionality to handle federated idp initiated saml logout requests.
 */
public class SAMLFedLogoutUtil extends InboundUtil {

    private static final Log log = LogFactory.getLog(SAMLFedLogoutUtil.class);
    private static boolean isBootStrapped = false;

    /**
     * Do the boostrap first.
     *
     * @throws FrameworkException
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
     * Build the StatusCode and statusMessage for Response.
     *
     * @param status
     * @param statMsg
     * @return
     */
    private static Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code.
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message.
        if (statMsg != null) {
            StatusMessage stateMesssage = new StatusMessageBuilder().buildObject();
            stateMesssage.setMessage(statMsg);
            stat.setStatusMessage(stateMesssage);
        }
        return stat;
    }

    /**
     * Build the secure random ID for logout response.
     *
     * @return
     */
    private static String createID() throws IdentityException {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new IdentityException("Error while building Secure Random ID", e);
        }
    }

    /**
     * store federated identity provider's configs into a map.
     *
     * @param identityProvider
     * @return
     */
    public static Map<String, String> getFederatedIdpConfigs(IdentityProvider identityProvider) {

        Property[] properties = identityProvider.getDefaultAuthenticatorConfig().getProperties();
        List<String> idpPropertyNames = Arrays.asList(SP_ENTITY_ID, SSO_URL, IS_AUTHN_RESP_SIGNED,
            INCLUDE_CERT, IS_LOGOUT_REQ_SIGNED);
        Map<String, String> fedIdPConfigs = new HashMap<>();

        for (Property property : properties) {
            if (idpPropertyNames.contains(property.getName())) {
                fedIdPConfigs.put(property.getName(), property.getValue());
                if (idpPropertyNames.size() == fedIdPConfigs.size()) {
                    break;
                }
            }
        }
        return fedIdPConfigs;
    }

    /**
     * build the error response.
     *
     * @param inResponseTo
     * @param statusCode
     * @param statusMsg
     * @return encoded response
     * @throws IdentityException
     */
    public static String buildErrorResponse(SAMLMessageContext context, String
        inResponseTo, String statusCode, String statusMsg) throws SAMLIdentityException {

        try {
            LogoutResponse errorResponse = buildResponse(context, inResponseTo, statusCode, statusMsg);
            return SSOUtils.encode(SSOUtils.marshall(errorResponse));
        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error Serializing the SAML Response", e);
        }
    }

    /**
     * Build the Logout Response.
     *
     * @param context
     * @param inResponseTo
     * @param statusCode
     * @param statusMsg
     * @return
     * @throws SAMLIdentityException
     */
    public static LogoutResponse buildResponse(SAMLMessageContext context, String inResponseTo,
                                               String statusCode, String statusMsg) throws SAMLIdentityException {

        try {
            doBootstrap();
            String issuerId = (String) context.getFedIdpConfigs().get(SP_ENTITY_ID);
            String acsUrl = (String) context.getFedIdpConfigs().get(SSO_URL);
            String isResSigned = (String) context.getFedIdpConfigs().get(IS_AUTHN_RESP_SIGNED);
            boolean includeCert = (context.getFedIdpConfigs().get(IdentityApplicationConstants.
                Authenticator.SAML2SSO.INCLUDE_CERT)).equals("true");

            IssuerBuilder issuerBuilder = new IssuerBuilder();
            Issuer issuer = issuerBuilder.buildObject();
            issuer.setValue(issuerId);

            LogoutResponse logoutResp = new LogoutResponseBuilder().buildObject();
            logoutResp.setID(createID());
            logoutResp.setInResponseTo(inResponseTo);
            logoutResp.setIssuer(issuer);
            logoutResp.setVersion(SAMLVersion.VERSION_20);
            logoutResp.setStatus(buildStatus(statusCode, statusMsg));
            logoutResp.setIssueInstant(new DateTime());
            logoutResp.setDestination(acsUrl);

            if (isResSigned.equals("true") && SSOConstants.StatusCodes.SUCCESS_CODE.equals(statusCode)) {
                SSOUtils.setSignature(logoutResp, null, null, includeCert,
                    new X509CredentialImpl(context.getSAMLLogoutRequest().getTenantDomain(), null));
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
     * Validate the signature of the LogoutRequest message against the given certificate.
     *
     * @param logoutRequest The logout request object if available.
     * @return
     * @throws IdentityException
     */
    public static boolean validateLogoutRequestSignature(LogoutRequest logoutRequest, SAMLMessageContext
        samlMessageContext) throws IdentityException {

        String issuer = logoutRequest.getIssuer().getValue();
        setX509Certificate(samlMessageContext);

        LogoutReqSignatureValidator signatureValidator = new LogoutReqSignatureValidator();
        try {
            if (samlMessageContext.getSAMLLogoutRequest().getQueryString() != null) {
                return signatureValidator.validateSignature(samlMessageContext.getSAMLLogoutRequest().getQueryString(),
                    issuer, samlMessageContext.getIdpCertificate());
            } else {
                return signatureValidator.validateXMLSignature(logoutRequest,
                    (X509Credential) samlMessageContext.getIdpCertificate(), null);
            }
        } catch (SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        }
    }

    /**
     * Generate the X509Certificate using the certificate string value in the identity provider's configuration.
     *
     * @param samlMessageContext
     * @throws SAMLIdentityException
     */

    public static void setX509Certificate(SAMLMessageContext samlMessageContext) throws SAMLIdentityException {

        String certificate = samlMessageContext.getFederatedIdp().getCertificate();
        byte[] certificateData = java.util.Base64.getDecoder().decode(certificate);
        java.security.cert.X509Certificate x509Certificate = null;

        try {
            x509Certificate = (java.security.cert.X509Certificate)
                CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificateData));
        } catch (CertificateException e) {
            throw new SAMLIdentityException("Error occurred while generating X509Certificate");
        }
        samlMessageContext.setIdpCertificate(x509Certificate);
    }
}
