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
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.LogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.LambdaExceptionUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLFedLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.ISSUER_FORMAT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
        SAML2SSO.IS_LOGOUT_REQ_SIGNED;
import static org.wso2.carbon.identity.base.IdentityConstants.TRUE;

/**
 * This class is responsible for validating the SAML single logout request from the federated IdP.
 */
public class LogoutRequestValidator {

    private static final Log log = LogFactory.getLog(LogoutRequestValidator.class);
    private SAMLMessageContext samlMessageContext;

    public LogoutRequestValidator(SAMLMessageContext samlMessageContext) {

        this.samlMessageContext = samlMessageContext;
    }

    /**
     * Validates the authentication request according to SAML SSO Web Browser Specification.
     *
     * @param logoutRequest {@link LogoutRequest} object to be validated.
     * @return boolean  Includes whether the request is valid.
     */
    public boolean isValidate(LogoutRequest logoutRequest) {

        // List of validators that we need to run before processing the logout.
        List<Consumer<LogoutRequest>> logoutRequestValidators = new ArrayList<>();

        // Validate the SAML version of the logout request.
        logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::isSAMLVersionValid));

        // Validate the issuer of the logout request.
        logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::isIssuerValid));

        // Validate the subject of the logout request.
        logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::isSubjectValid));

        // Validate the signature of the logout request.
        logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::isValidLogoutReqSignature));

        // Run all validators against the logout request to validate.
        for (Consumer<LogoutRequest> validator : logoutRequestValidators) {
            validator.accept(logoutRequest);
            if (!samlMessageContext.getValidStatus()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate the SAML version of the logout request.
     *
     * @param logoutRequest {@link LogoutRequest} object to be validated.
     * @throws SAMLIdentityException If SAML version validation fails.
     */
    private void isSAMLVersionValid(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (!(SAMLVersion.VERSION_20.equals(logoutRequest.getVersion()))) {
            String notification = "Invalid SAML Version in Logout Request. SAML Version should be equal to 2.0";
            if (log.isDebugEnabled()) {
                log.debug(notification);
            }
            samlMessageContext.setValidStatus(false);
            String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext, logoutRequest.getID(),
                    SSOConstants.StatusCodes.VERSION_MISMATCH, notification);
            throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                    samlMessageContext.getRelayState());
        }
    }

    /**
     * Validate the issuer of the logout request.
     *
     * @param logoutRequest {@link LogoutRequest} object to be validated.
     * @throws SAMLIdentityException If Issuer of the Logout Request validation fails.
     */
    private void isIssuerValid(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (logoutRequest.getIssuer().getValue() != null) {
            if (StringUtils.isBlank(logoutRequest.getIssuer().getFormat()) ||
                    !(ISSUER_FORMAT.equals(logoutRequest.getIssuer().getFormat()))) {
                String notification = "Invalid Issuer Format in the logout request";
                if (log.isDebugEnabled()) {
                    log.debug(notification);
                }
                samlMessageContext.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext, logoutRequest.getID(),
                        SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
                throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                        samlMessageContext.getRelayState());
            }
        } else {
            String notification = "Issuer value cannot be null in the Logout Request";
            if (log.isDebugEnabled()) {
                log.debug(notification);
            }
            samlMessageContext.setValidStatus(false);
            String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext, logoutRequest.getID(),
                    SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
            throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                    samlMessageContext.getRelayState());
        }
    }

    /**
     * Validate the subject of the logout request.
     *
     * @param logoutRequest {@link LogoutRequest} object to be validated.
     * @throws SAMLIdentityException If Subject of the Logout Request validation fails.
     */
    private void isSubjectValid(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (logoutRequest.getNameID() == null && logoutRequest.getBaseID() == null
                && logoutRequest.getEncryptedID() == null) {
            String notification = "Subject Name should be specified in the Logout Request";
            if (log.isDebugEnabled()) {
                log.debug(notification);
            }
            samlMessageContext.setValidStatus(false);
            String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext, logoutRequest.getID(),
                    SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
            throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                    samlMessageContext.getRelayState());
        }
    }

    /**
     * Validate the signature of the logout request.
     *
     * @param logoutRequest {@link LogoutRequest} object to be validated.
     * @throws SAMLIdentityException If Signature of the Logout Request validation fails.
     */
    private void isValidLogoutReqSignature(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (TRUE.equals(samlMessageContext.getFedIdPConfigs().get(IS_LOGOUT_REQ_SIGNED))) {
            if (!SAMLFedLogoutUtil.isValidSignature(logoutRequest, samlMessageContext)) {
                String notification = "Signature validation failed for logout request with issuer: "
                        + logoutRequest.getIssuer().getValue();
                if (log.isDebugEnabled()) {
                    log.debug(notification);
                }
                samlMessageContext.setValidStatus(false);
                String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext,
                        logoutRequest.getID(), SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
                throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                        samlMessageContext.getRelayState());
            }
        }

    }
}
