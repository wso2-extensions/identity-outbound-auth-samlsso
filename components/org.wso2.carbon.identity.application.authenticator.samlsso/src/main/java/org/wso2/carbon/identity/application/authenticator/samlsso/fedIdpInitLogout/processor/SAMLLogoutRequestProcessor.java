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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.processor;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.dao.SessionDetailsDAO;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.util.LambdaExceptionUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.util.SAMLFedLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
    SAML2SSO.IS_LOGOUT_REQ_SIGNED;

/**
 * This class is responsible for doing the actual processing of the logout request.
 * It does this by validating the IdentityRequest and passing it on to the authentication framework for logout.
 */
public class SAMLLogoutRequestProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(SAMLLogoutRequestProcessor.class);
    private SAMLMessageContext samlMessageContext;

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        return (identityRequest instanceof SAMLLogoutRequest);
    }

    /**
     * main process is carried out. validate the logout request according to the saml spec.
     * A MessageContext is created so that any needed properties can be preserved for the outflow.
     * The request is passed to the framework through the buildResponseForFrameworkLogout() method.
     *
     * @param identityRequest
     * @return
     * @throws SAMLIdentityException
     */
    @Override
    public FrameworkLogoutResponse.FrameworkLogoutResponseBuilder process(IdentityRequest identityRequest)
        throws SAMLIdentityException {

        samlMessageContext = new SAMLMessageContext(identityRequest, new HashMap<String, String>());

        try {
            XMLObject samlRequest;
            if (samlMessageContext.getSAMLLogoutRequest().isPost()) {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decodeForPost(samlMessageContext.getSamlRequest()));
            } else {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decode(samlMessageContext.getSamlRequest()));
            }

            LogoutRequest logoutRequest;
            if (samlRequest instanceof LogoutRequest) {
                logoutRequest = (LogoutRequest) samlRequest;
                samlMessageContext.setValidStatus(true);
            } else {
                samlMessageContext.setValidStatus(false);
                throw new SAMLIdentityException("Invalid Single Logout SAML Request");
            }

            // List of validators that we need to run before processing the logout.
            List<Consumer<LogoutRequest>> logoutRequestValidators = new ArrayList<>();

            // Validate session indexes of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::validateSessionIndex));

            // Validate the issuer of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::validateSamlVersion));

            // Validate the issuer of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::validateIssuer));

            // Validate the subject of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::validateSubject));

            // Validate the signature of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtil.rethrowConsumer(this::validateSignature));

            // Run all validators against the logout request to validate.
            for (Consumer<LogoutRequest> validator : logoutRequestValidators) {
                validator.accept(logoutRequest);
            }

            //build the logout response
            if (samlMessageContext.getValidStatus()) {
                LogoutResponse logoutResp = SAMLFedLogoutUtil.buildResponse(samlMessageContext, logoutRequest.getID(),
                    SSOConstants.StatusCodes.SUCCESS_CODE, null);
                samlMessageContext.setResponse(SSOUtils.encode(SSOUtils.marshall(logoutResp)));
                samlMessageContext.setAcsUrl(logoutResp.getDestination());
            }
        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error when processing the Logout Request");
        }
        return buildResponseForFrameworkLogout(samlMessageContext);
    }

    /**
     * Build the request for the framework logout.
     *
     * @param context
     * @return
     */
    protected FrameworkLogoutResponse.FrameworkLogoutResponseBuilder buildResponseForFrameworkLogout
    (SAMLMessageContext context) {

        IdentityRequest identityRequest = context.getRequest();
        Map<String, String[]> parameterMap = identityRequest.getParameterMap();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        Set<Map.Entry<String, String>> headers = new HashMap(identityRequest.getHeaderMap()).entrySet();
        Iterator<Map.Entry<String, String>> iterator = headers.iterator();
        while (iterator.hasNext()){
            authenticationRequest.addHeader(iterator.next().getKey(), iterator.next().getValue());
        }
        authenticationRequest.setTenantDomain(identityRequest.getTenantDomain());
        authenticationRequest.setRelyingParty(getRelyingPartyId(context));
        authenticationRequest.setType(getType(context));
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context),
                StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path " +
                getCallbackPath(context), e);
        }
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT, new String[]{"true"});
        authenticationRequest.addRequestQueryParam("sessionId", new String[]{context.getSessionID()});

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionDataKey = UUIDGenerator.generateUUID();
        authRequest.setValidityPeriod(TimeUnit.MINUTES.toNanos(IdentityUtil.getOperationCleanUpTimeout()));
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);

        InboundUtil.addContextToCache(sessionDataKey, context);

        FrameworkLogoutResponse.FrameworkLogoutResponseBuilder responseBuilder =
            new FrameworkLogoutResponse.FrameworkLogoutResponseBuilder(context);
        responseBuilder.setContextKey(sessionDataKey);
        responseBuilder.setCallbackPath(getCallbackPath(context));
        responseBuilder.setAuthType(getType(context));
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    /**
     * Retrieve the session details of saml index and identity provider configurations.
     *
     * @param sessionIndex
     * @throws SAMLIdentityException
     */
    private void getSessionInfo(String sessionIndex) throws SAMLIdentityException {

        try {
            //get the session details relevant to idp session index from database
            SessionDetailsDAO sessionDetailsDAO = new SessionDetailsDAO();
            Map<String, String> sessionDetails = sessionDetailsDAO.getSessionDetails
                (samlMessageContext.getIdpSessionId());

            if (sessionDetails != null) {
                IdentityProvider identityProvider = IdentityProviderManager.getInstance().getIdPById
                    (sessionDetails.get("idpID"), (samlMessageContext.getSAMLLogoutRequest().getTenantDomain()));
                Map<String, String> fedIdpConfigs = SAMLFedLogoutUtil.getFederatedIdpConfigs(identityProvider);
                samlMessageContext.setSessionID(sessionDetails.get("sessionID"));
                samlMessageContext.setFederatedIdp(identityProvider);
                samlMessageContext.setFedIdpConfigs(fedIdpConfigs);
            }
        } catch (SQLException | IdentityProviderManagementException e) {
            throw new SAMLIdentityException("Error occured while retrieving the session details of " + sessionIndex, e);
        }
    }

    /**
     * Validate session indexes of the logout request.
     *
     * @param logoutRequest
     * @throws SAMLIdentityException
     */
    private void validateSessionIndex(LogoutRequest logoutRequest)
        throws SAMLIdentityException {

        if (logoutRequest.getSessionIndexes() != null) {
            String sessionIndex = logoutRequest.getSessionIndexes().size() > 0 ? logoutRequest
                .getSessionIndexes().get(0).getSessionIndex() : null;
            samlMessageContext.setIdpSessionId(sessionIndex);
            getSessionInfo(sessionIndex);
        } else {
            String notification = "Could not extract the Session Index from Logout Request.";
            if (log.isDebugEnabled()) {
                log.debug(notification);
            }
            String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext, logoutRequest.getID(),
                SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
            throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                samlMessageContext.getRelayState());
        }
    }

    /**
     * validate the SAML version of the logout request.
     *
     * @param logoutRequest
     * @throws SAMLIdentityException
     */
    private void validateSamlVersion(LogoutRequest logoutRequest) throws SAMLIdentityException {

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
     * @param logoutRequest
     * @throws SAMLIdentityException
     */
    private void validateIssuer(LogoutRequest logoutRequest) throws SAMLIdentityException {

        if (logoutRequest.getIssuer().getValue() != null) {
            if (StringUtils.isBlank(logoutRequest.getIssuer().getFormat())) {
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
     * @param logoutRequest
     * @throws SAMLIdentityException
     */
    private void validateSubject(LogoutRequest logoutRequest) throws SAMLIdentityException {

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
     * Validate signature of the logout request.
     *
     * @param logoutRequest
     * @throws SAMLIdentityException
     */
    private void validateSignature(LogoutRequest logoutRequest) throws SAMLIdentityException {

        try {
            if ((samlMessageContext.getFedIdpConfigs().get(IS_LOGOUT_REQ_SIGNED)).equals("true")) {
                if (!SAMLFedLogoutUtil.validateLogoutRequestSignature(logoutRequest, samlMessageContext)) {
                    String notification = "Signature validation for Logout Request failed";
                    if (log.isDebugEnabled()) {
                        log.debug(notification);
                    }
                    samlMessageContext.setValidStatus(false);
                    String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(samlMessageContext,
                        logoutRequest.getID(),
                        SSOConstants.StatusCodes.REQUESTOR_ERROR, notification);
                    throw new SAMLIdentityException(notification, errorResponse, logoutRequest.getDestination(),
                        samlMessageContext.getRelayState());
                }
            }
        } catch (IdentityException e) {
            throw new SAMLIdentityException("Error occurred validating signature of Logout Request", e);
        }
    }

    @Override
    public String getType(IdentityMessageContext context) {

        return SSOConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {

        return null;
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext context) {

        return null;
    }
}
