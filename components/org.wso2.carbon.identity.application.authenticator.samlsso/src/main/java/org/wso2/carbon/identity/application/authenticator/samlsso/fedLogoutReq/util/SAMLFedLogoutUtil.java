package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.util;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.Validators.LogoutReqSignatureValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.ByteArrayInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.*;

public class SAMLFedLogoutUtil extends InboundUtil {

    private static final Log log = LogFactory.getLog(IdentityProvider.class);

    private static boolean isBootStrapped = false;

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

    public static Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code.
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message.
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    public static String createID() {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            //log.error("Error while building Secure Random ID", e);
            //TODO : throw exception and break the flow
        }
        return null;
    }


    public static Map<String, String> getFederatedIdpConfigs(IdentityProvider identityProvider) {

        Map<String, String> fedIdpProperties= new HashMap<>();
        Property[] properties = identityProvider.getDefaultAuthenticatorConfig().getProperties();
        if (properties != null) {
            for (Property property : properties) {
                if (SP_ENTITY_ID.equals(property.getName())) {
                    fedIdpProperties.put(SP_ENTITY_ID, property.getValue());
                }
                if (IDP_ENTITY_ID.equals(property.getName())) {
                    fedIdpProperties.put(IDP_ENTITY_ID, property.getValue());
                }
                if (SSO_URL.equals(property.getName())) {
                    fedIdpProperties.put(SSO_URL, property.getValue());
                }
                if (IS_LOGOUT_REQ_SIGNED.equals(property.getName())) {
                    fedIdpProperties.put(IS_LOGOUT_REQ_SIGNED, property.getValue());
                }
                if (INCLUDE_CERT.equals(property.getName())) {
                    fedIdpProperties.put(INCLUDE_CERT, property.getValue());
                }
                if (LOGOUT_REQ_URL.equals(property.getName())) {
                    fedIdpProperties.put(LOGOUT_REQ_URL, property.getValue());
                }
                if (IS_AUTHN_RESP_SIGNED.equals(property.getName())) {
                    fedIdpProperties.put(IS_AUTHN_RESP_SIGNED, property.getValue());
                }

            }

        }
        return fedIdpProperties;
    }

    /**
     * build the error response
     *
     * @param inResponseTo
     * @param statusCode
     * @param statusMsg
     * @return decoded response
     * @throws IdentityException
     */
    public static String buildErrorResponse(SAMLMessageContext context, String inResponseTo, String statusCode, String statusMsg)
        throws SAMLSSOException, SAMLIdentityException {

        LogoutResponse errorResponse = buildResponse(context, inResponseTo, statusCode, statusMsg);
        return SSOUtils.encode(SSOUtils.marshall(errorResponse));
    }


    public static LogoutResponse buildResponse(SAMLMessageContext context, String inResponseTo, String statusCode, String statusMsg) throws SAMLIdentityException{

        try {
            doBootstrap();
        } catch (FrameworkException e) {
            throw new SAMLIdentityException("Error in bootstrapping the OpenSAML2 library",e);
        }

        String issuerId = context.getFedIdpConfigs().get(SP_ENTITY_ID).toString();
        String acsUrl = context.getFedIdpConfigs().get(SSO_URL).toString();
        String isResSigned = context.getFedIdpConfigs().get(IS_AUTHN_RESP_SIGNED).toString();
        boolean includeCert = (context.getFedIdpConfigs().get(INCLUDE_CERT)).equals("true");

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

        try {
            if (isResSigned.equals("true") && SAMLConstants.StatusCodes.SUCCESS_CODE.equals(statusCode)) {
                SSOUtils.setSignature(logoutResp, null, null, includeCert,
                    new X509CredentialImpl(context.getSAMLLogoutRequest().getTenantDomain(), null));
            }
        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error occurred while setting the signature of logout response",e);
        }

        return logoutResp;

    }

    /**
     * Validate the signature of the LogoutRequest message against the given certificate.
     *
     * @param logoutRequest The logout request object if available.
     * @return
     * @throws IdentityException
     */
    public static boolean validateLogoutRequestSignature(LogoutRequest logoutRequest, SAMLMessageContext context) throws IdentityException {


        String issuer = logoutRequest.getIssuer().getValue();
        setX509Certificate(context);

        LogoutReqSignatureValidator signatureValidator= new LogoutReqSignatureValidator();
        try {
            if (context.getSAMLLogoutRequest().getQueryString() != null) {
                return signatureValidator.validateSignature(context.getSAMLLogoutRequest().getQueryString(), issuer, context.getIdpCertificate());
            } else {
                return signatureValidator.validateXMLSignature(logoutRequest, (X509Credential) context.getIdpCertificate(), null);
            }
        }catch (SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        }
    }

    public static void setX509Certificate(SAMLMessageContext context) {

        String cert = context.getFederatedIdp().getCertificate();
        byte[] certificateData = java.util.Base64.getDecoder().decode(cert);
        java.security.cert.X509Certificate certificate = null;
        try {
            certificate = (java.security.cert.X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(certificateData));
        } catch (CertificateException e) {
            e.printStackTrace();//todo
        }
        context.setIdpCertificate(certificate);
    }



}
