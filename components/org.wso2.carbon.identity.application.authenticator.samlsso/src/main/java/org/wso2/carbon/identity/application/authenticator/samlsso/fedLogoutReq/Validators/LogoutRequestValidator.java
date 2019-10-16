package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.Validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.LogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.util.SAMLFedLogoutUtil;
import org.wso2.carbon.identity.base.IdentityException;


public class LogoutRequestValidator {
    private static final Log log = LogFactory.getLog(LogoutRequestValidator.class);
    private SAMLMessageContext context;

    public LogoutRequestValidator(SAMLMessageContext context) throws IdentityException {
        this. context = context;
    }

    /**
     * Validates the logout request according to SAML SSO Web Browser Specification
     *
     */
    public void validate() throws SAMLIdentityException{


        LogoutRequest logoutReq = context.getLogoutReq();
        try {
            // Validate the version
            if (!(SAMLVersion.VERSION_20.equals(logoutReq.getVersion()))) {
                String errorMessage = "Invalid SAML Version in Logout Request. SAML Version should be equal to 2.0";
                log.error(errorMessage);
                context.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutReq.getID(),
                    SAMLConstants.StatusCodes.VERSION_MISMATCH, errorMessage);
                throw new SAMLIdentityException(errorMessage, errorResponse, logoutReq.getDestination(), context.getRelayState());

            }
            // Issuer MUST NOT be null
            if (logoutReq.getIssuer() == null) {
                String errorMessage = "Issuer should be mentioned in the Logout Request";
                log.error(errorMessage);
                context.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutReq.getID(),
                    SAMLConstants.StatusCodes.REQUESTOR_ERROR, errorMessage);
                throw new SAMLIdentityException(errorMessage, errorResponse, logoutReq.getDestination(), context.getRelayState());

            } else if (logoutReq.getIssuer().getValue() == null) {
                String errorMessage = "Issuer value cannot be null in the Logout Request";
                log.error(errorMessage);
                context.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutReq.getID(),
                    SAMLConstants.StatusCodes.REQUESTOR_ERROR, errorMessage);
                throw new SAMLIdentityException(errorMessage, errorResponse, logoutReq.getDestination(), context.getRelayState());
            }


            // Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity
            if (StringUtils.isBlank(logoutReq.getIssuer().getFormat())) {
                if (!(SAMLConstants.ISSUER_FORMAT.equals(logoutReq.getIssuer().getFormat()))) {
                    String errorMessage = "Invalid Issuer Format in the logout request";
                    log.error(errorMessage);
                    context.setValidStatus(false);
                    String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutReq.getID(),
                        SAMLConstants.StatusCodes.REQUESTOR_ERROR, errorMessage);
                    throw new SAMLIdentityException(errorMessage, errorResponse, logoutReq.getDestination(), context.getRelayState());

                }
            }

            // Validate the subject of the logout request.
            if (logoutReq.getNameID() == null && logoutReq.getBaseID() == null
                && logoutReq.getEncryptedID() == null) {
                String errorMessage = "Subject Name should be specified in the Logout Request";
                log.error(errorMessage);
                context.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutReq.getID(),
                    SAMLConstants.StatusCodes.REQUESTOR_ERROR, errorMessage);
                throw new SAMLIdentityException(errorMessage, errorResponse, logoutReq.getDestination(), context.getRelayState());

            }

        }catch (SAMLSSOException e) {
           throw new SAMLIdentityException("Error occurred while building the error response ",e);
        }

    }

}
