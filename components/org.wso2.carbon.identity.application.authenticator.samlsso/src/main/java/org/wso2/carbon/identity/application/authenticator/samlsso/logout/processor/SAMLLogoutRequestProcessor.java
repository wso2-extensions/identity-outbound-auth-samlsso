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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.core.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.dao.SessionInfoDAO;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators.LogoutRequestValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.LOGOUT;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.
        AnalyticsAttributes.SESSION_ID;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.StatusCodes.SUCCESS_CODE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
        SAML2SSO.IS_SLO_REQUEST_ACCEPTED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.COMMONAUTH;
import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.IDP_NAME;
import static org.wso2.carbon.identity.base.IdentityConstants.IDENTITY_DEFAULT_ROLE;
import static org.wso2.carbon.identity.base.IdentityConstants.ServerConfig.SAMLSSO;
import static org.wso2.carbon.identity.base.IdentityConstants.TRUE;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * This class processes the SAML single logout request from the federated IdP.
 */
public class SAMLLogoutRequestProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(SAMLLogoutRequestProcessor.class);

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        return (identityRequest instanceof SAMLLogoutRequest);
    }

    /**
     * Processes the authentication request according to SAML SSO Web Browser Specification.
     *
     * @param identityRequest {@link IdentityRequest} Identity Request of SAML Logout Request type.
     * @return FrameworkLogoutResponse.FrameworkLogoutResponseBuilder instance.
     * @throws SAMLIdentityException Error when processing the Logout Request.
     */
    @Override
    public FrameworkLogoutResponse.FrameworkLogoutResponseBuilder process(IdentityRequest identityRequest)
            throws SAMLIdentityException {

        SAMLMessageContext<String, String> samlMessageContext = new SAMLMessageContext<>(identityRequest,
                new HashMap<>());

        try {
            XMLObject samlRequest;
            if (samlMessageContext.getSAMLLogoutRequest().isPost()) {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decodeForPost(identityRequest.getParameter
                        (SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)));
            } else {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decode(identityRequest.getParameter
                        (SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)));
            }

            LogoutRequest logoutRequest;
            if (samlRequest instanceof LogoutRequest) {
                logoutRequest = (LogoutRequest) samlRequest;
                samlMessageContext.setValidStatus(true);
            } else {
                samlMessageContext.setValidStatus(false);
                throw new SAMLIdentityException("Invalid Single Logout SAML Request");
            }

            samlMessageContext.setIdPSessionID(SAMLLogoutUtil.getSessionIndex(logoutRequest));
            if (StringUtils.isNotBlank(samlMessageContext.getIdPSessionID())) {
                populateContextWithSessionDetails(samlMessageContext);
            }

            if (Boolean.parseBoolean(samlMessageContext.getFedIdPConfigs().get(IS_SLO_REQUEST_ACCEPTED))) {
                throw new SAMLIdentityException("Single logout request from the federated IdP: "
                        + samlMessageContext.getFederatedIdP().getIdentityProviderName() + " is not accepted");
            }
            LogoutRequestValidator logoutRequestValidator = new LogoutRequestValidator(samlMessageContext);
            if (logoutRequestValidator.isValidate(logoutRequest)) {
                LogoutResponse logoutResp = SAMLLogoutUtil.buildResponse(samlMessageContext, logoutRequest.getID(),
                        SUCCESS_CODE, null);
                samlMessageContext.setResponse(SSOUtils.encode(SSOUtils.marshall(logoutResp)));
                samlMessageContext.setAcsUrl(logoutResp.getDestination());
            }
            return buildResponseForFrameworkLogout(samlMessageContext);

        } catch (SAMLSSOException e) {
            throw new SAMLIdentityException("Error when processing the Logout Request.", e);
        }
    }

    /**
     * Build the authentication request for the framework logout.
     *
     * @param samlMessageContext {@link SAMLMessageContext} object which holds details on logout flow.
     * @return FrameworkLogoutResponse.FrameworkLogoutResponseBuilder instance.
     */
    private FrameworkLogoutResponse.FrameworkLogoutResponseBuilder buildResponseForFrameworkLogout
            (SAMLMessageContext<String, String> samlMessageContext) {

        IdentityRequest identityRequest = samlMessageContext.getRequest();
        Map<String, String[]> parameterMap = identityRequest.getParameterMap();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        if (identityRequest.getHeaderMap() != null) {
            identityRequest.getHeaderMap().forEach(authenticationRequest::addHeader);
        }
        authenticationRequest.setTenantDomain(samlMessageContext.getTenantDomain());
        authenticationRequest.setRelyingParty(getRelyingPartyId(samlMessageContext));
        authenticationRequest.setType(getType(samlMessageContext));
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(samlMessageContext),
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path: " +
                    getCallbackPath(samlMessageContext), e);
        }
        authenticationRequest.addRequestQueryParam(LOGOUT, new String[]{TRUE});
        authenticationRequest.addRequestQueryParam(SESSION_ID, new String[]{samlMessageContext.getSessionID()});

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionDataKey = UUIDGenerator.generateUUID();
        authRequest.setValidityPeriod(TimeUnit.MINUTES.toNanos(IdentityUtil.getOperationCleanUpTimeout()));
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);

        InboundUtil.addContextToCache(sessionDataKey, samlMessageContext);

        FrameworkLogoutResponse.FrameworkLogoutResponseBuilder responseBuilder =
                new FrameworkLogoutResponse.FrameworkLogoutResponseBuilder(samlMessageContext);
        responseBuilder.setContextKey(sessionDataKey);
        responseBuilder.setCallbackPath(getCallbackPath(samlMessageContext));
        responseBuilder.setAuthType(getType(samlMessageContext));
        String commonAuthURL = IdentityUtil.getServerURL(COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    /**
     * Populate SAMLMessageContext with session details of the SAML index.
     *
     * @param samlMessageContext {@link SAMLMessageContext} object which has details on logout flow.
     * @throws SAMLIdentityException Error while retrieving the session details.
     */
    private void populateContextWithSessionDetails(SAMLMessageContext<String, String> samlMessageContext)
            throws SAMLIdentityException {

        SessionInfoDAO sessionInfoDAO = new SessionInfoDAO();
        Map<String, String> sessionDetails = sessionInfoDAO.getSessionDetails
                (samlMessageContext.getIdPSessionID());
        if (sessionDetails != null) {
            if (StringUtils.isNotBlank(samlMessageContext.getSAMLLogoutRequest().getTenantDomain())) {
                samlMessageContext.setTenantDomain(samlMessageContext.getSAMLLogoutRequest().getTenantDomain());
            } else {
                samlMessageContext.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
            }
            IdentityProvider identityProvider = null;
            try {
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(
                        sessionDetails.get(IDP_NAME), samlMessageContext.getTenantDomain());
            } catch (IdentityProviderManagementException e) {
                String notification = "Error when getting the Identity Provider by IdP name : "
                        + sessionDetails.get(IDP_NAME) + "with tenant domain: " + samlMessageContext.getTenantDomain();
                if (log.isDebugEnabled()) {
                    log.debug(notification);
                }
                throw new SAMLIdentityException(notification, e);
            }
            samlMessageContext.setSessionID(sessionDetails.get(SESSION_ID));
            samlMessageContext.setFederatedIdP(identityProvider);
            samlMessageContext.setFedIdPConfigs(SAMLLogoutUtil.getFederatedIdPConfigs(identityProvider));
        }
    }

    @Override
    public String getType(IdentityMessageContext context) {

        return SAMLSSO;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return IdentityUtil.getServerURL(IDENTITY_DEFAULT_ROLE, false, false);
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
