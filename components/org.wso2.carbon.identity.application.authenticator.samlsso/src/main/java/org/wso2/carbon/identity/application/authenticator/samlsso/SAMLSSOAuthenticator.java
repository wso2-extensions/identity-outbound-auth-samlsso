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

package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStateInfo;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationContextProperty;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.SAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.StateInfo;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.SubProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_ARTIFACT_ID;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_RESP;
import static org.wso2.carbon.identity.base.IdentityConstants.FEDERATED_IDP_SESSION_ID;

public class SAMLSSOAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8097512332218044859L;
    public static final String AS_REQUEST = "AS_REQUEST";
    public static final String AUTHENTICATION_CONTEXT = "AUTHENTICATION_CONTEXT";

    private static final String AS_RESPONSE = "AS_RESPONSE";
    private static final String AUTH_PARAM = "$authparam";
    private static final String DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX = "\\$authparam\\{(\\w+)}";
    private static final Pattern authParamDynamicQueryPattern = Pattern.compile(DYNAMIC_AUTH_PARAMS_LOOKUP_REGEX);

    private static final Log log = LogFactory.getLog(SAMLSSOAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside canHandle()");
        }

        return request.getParameter(HTTP_POST_PARAM_SAML2_RESP) != null ||
                request.getParameter(HTTP_POST_PARAM_SAML2_ARTIFACT_ID) != null;

    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        String idpURL = authenticatorProperties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL);
        String ssoUrl;
        boolean isPost = false;

        try {
            String requestMethod = authenticatorProperties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD);

            if (requestMethod != null && requestMethod.trim().length() != 0) {
                if (SSOConstants.POST.equalsIgnoreCase(requestMethod)) {
                    isPost = true;
                } else if (AS_REQUEST.equalsIgnoreCase(requestMethod)) {
                    isPost = context.getAuthenticationRequest().isPost();
                }
            }

            // Resolves dynamic query parameters from "Additional Query Parameters".
            resolveDynamicParameter(request, context);

            if (isPost) {
                sendPostRequest(request, response, false, idpURL, context);
            } else {
                SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
                saml2SSOManager.init(context.getTenantDomain(), context.getAuthenticatorProperties(),
                        context.getExternalIdP().getIdentityProvider());
                ssoUrl = saml2SSOManager.buildRequest(request, false, false, idpURL, context);
                generateAuthenticationRequest(request, response, ssoUrl, authenticatorProperties);

            }
        } catch (SAMLSSOException e) {
            throw new AuthenticationFailedException(e.getErrorCode(), e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(ErrorMessages.UNSUPPORTED_ENCODING_EXCEPTION.getCode(),
                    e.getMessage(), e);
        }
    }

    /**
     * Resolves dynamic query parameters from "Additional Query Parameters" string.
     *
     * @param request servlet request
     * @param context authentication context
     * @throws UnsupportedEncodingException if the character encoding is unsupported
     */
    private void resolveDynamicParameter(HttpServletRequest request, AuthenticationContext context) throws
            UnsupportedEncodingException {

        String queryParameters = context.getAuthenticatorProperties().get(FrameworkConstants.QUERY_PARAMS);
        if (queryParameters != null) {
            context.getAuthenticatorProperties()
                    .put(FrameworkConstants.QUERY_PARAMS, getResolvedQueryParams(request, context, queryParameters));
        }
    }

    /**
     * Checks for any dynamic query parameters and replaces it with the values in the SAML request.
     *
     * @param request          servlet request
     * @param context          authentication context
     * @param queryParamString query parameters string
     * @return resolved query parameter string
     * @throws UnsupportedEncodingException if the character encoding is unsupported
     */
    private String getResolvedQueryParams(HttpServletRequest request, AuthenticationContext context,
                                          String queryParamString) throws UnsupportedEncodingException {

        Map<String, String> queryMap = SSOUtils.getQueryMap(queryParamString);
        StringBuilder queryBuilder = new StringBuilder();
        for (Map.Entry<String, String> queryParamEntry : queryMap.entrySet()) {
            String resolvedQueryParamValue = getResolvedQueryParamValue(request, context, queryParamEntry);

            if (queryBuilder.length() > 0) {
                // Add an & if this is not the first query param.
                queryBuilder.append('&');
            }

            queryBuilder.append(URLEncoder.encode(queryParamEntry.getKey(), StandardCharsets.UTF_8.name())).append("=")
                    .append((URLEncoder.encode(resolvedQueryParamValue, StandardCharsets.UTF_8.name())));
        }
        return queryBuilder.toString();
    }

    private String getResolvedQueryParamValue(HttpServletRequest request, AuthenticationContext context,
                                              Map.Entry<String, String> queryParam) {

        String resolvedQueryParamValue = queryParam.getValue();

        if (isDynamicQueryParam(resolvedQueryParamValue)) {
            String inboundQueryParamKey = removeEnclosingParenthesis(resolvedQueryParamValue);
            String[] authRequestParamValues = context.getAuthenticationRequest()
                    .getRequestQueryParam(inboundQueryParamKey);
            String currentRequestParamValue = request.getParameter(inboundQueryParamKey);
            if (ArrayUtils.isNotEmpty(authRequestParamValues)) {
                resolvedQueryParamValue = authRequestParamValues[0];
            } else if (StringUtils.isNotBlank(currentRequestParamValue)) {
                resolvedQueryParamValue = currentRequestParamValue;
            } else {
                // If the dynamic query param value is not sent in the inbound request we are sending an empty
                // string for the dynamic query value.
                resolvedQueryParamValue = StringUtils.EMPTY;
            }
        } else if (isDynamicAuthContextParam(resolvedQueryParamValue)) {
            Matcher matcher = authParamDynamicQueryPattern.matcher(resolvedQueryParamValue);
            if (matcher.find()) {
                String paramName = matcher.group(1);
                String valueFromRuntimeParams = getRuntimeParams(context).get(paramName);
                if (StringUtils.isNotEmpty(valueFromRuntimeParams)) {
                    if (log.isDebugEnabled()) {
                        log.debug(queryParam.getKey() + "=" + queryParam.getValue() + " was replaced as "
                                + queryParam.getKey() + "=" + valueFromRuntimeParams);
                    }
                    return valueFromRuntimeParams;
                }
            }

            return StringUtils.EMPTY;
        }
        return resolvedQueryParamValue;
    }

    private boolean isDynamicAuthContextParam(String resolvedQueryParamValue) {

        return StringUtils.startsWith(resolvedQueryParamValue, AUTH_PARAM);
    }

    private String removeEnclosingParenthesis(String queryParamValue) {
        if (isEnclosedWithParenthesis(queryParamValue)) {
            return queryParamValue.substring(1, queryParamValue.length() - 1);
        } else {
            return queryParamValue;
        }
    }

    private boolean isDynamicQueryParam(String queryParamValue) {
        return isEnclosedWithParenthesis(queryParamValue) && queryParamValue.length() > 2;
    }

    private boolean isEnclosedWithParenthesis(String queryParamValue) {
        return StringUtils.startsWith(queryParamValue, "{") && StringUtils.endsWith(queryParamValue, "}");
    }

    private void generateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                               String ssoUrl, Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        try {
            String domain = request.getParameter("domain");

            if (domain != null) {
                ssoUrl = ssoUrl + "&fidp=" + domain;
            }

            if (authenticatorProperties != null) {
                String queryString = authenticatorProperties
                        .get(FrameworkConstants.QUERY_PARAMS);
                if (queryString != null) {
                    if (!queryString.startsWith("&")) {
                        ssoUrl = ssoUrl + "&" + queryString;
                    } else {
                        ssoUrl = ssoUrl + queryString;
                    }
                }
            }
            response.sendRedirect(ssoUrl);
        } catch (IOException e) {
            throw new AuthenticationFailedException(ErrorMessages.IO_ERROR.getCode(),
                    "Error while sending the redirect to federated SAML IdP.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String subject = null;
        try {
            SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
            saml2SSOManager.init(context.getTenantDomain(), context.getAuthenticatorProperties(),
                    context.getExternalIdP().getIdentityProvider());
            // unfortunately the SAML2SSOManager interface does not allow passing authentication
            // context. this is required to support to build context aware SAML requests - and then
            // to validate the corresponding SAML response.this is a workaround not to break the
            // interface - and we remove this request attribute in the finally block of this method.
            request.setAttribute(AUTHENTICATION_CONTEXT, context);
            saml2SSOManager.processResponse(request);
            Map<ClaimMapping, String> receivedClaims = (Map<ClaimMapping, String>) request
                    .getSession(false).getAttribute("samlssoAttributes");

            String isSubjectInClaimsProp = context.getAuthenticatorProperties().get(
                    IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS);
            if ("true".equalsIgnoreCase(isSubjectInClaimsProp)) {
                subject = FrameworkUtils.getFederatedSubjectFromClaims(
                        context.getExternalIdP().getIdentityProvider(), receivedClaims);
                if (subject == null) {
                    log.warn("Subject claim could not be found amongst attribute statements. " +
                            "Defaulting to Name Identifier.");
                }
            }

            if (subject == null) {
                subject = (String) request.getSession().getAttribute("username");
            }

            if (StringUtils.isBlank(subject)) {
                throw new SAMLSSOException(ErrorMessages.FEDERATED_USER_IDENTIFIER_NOT_FOUND.getCode(),
                        ErrorMessages.FEDERATED_USER_IDENTIFIER_NOT_FOUND.getMessage());
            }

            Object sessionIndexObj = request.getSession(false).getAttribute(SSOConstants.IDP_SESSION);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);
            String sessionIndex = null;

            if (sessionIndexObj != null) {
                sessionIndex = (String) sessionIndexObj;
            }

            StateInfo stateInfoDO = new StateInfo();
            stateInfoDO.setSessionIndex(sessionIndex);
            stateInfoDO.setSubject(subject);
            stateInfoDO.setNameQualifier(nameQualifier);
            stateInfoDO.setSpNameQualifier(spNameQualifier);
            context.setStateInfo(stateInfoDO);

            // Adding session index with the federated IdP name as a property into the authentication context.
            context.setProperty(FEDERATED_IDP_SESSION_ID + context.getExternalIdP().getIdentityProvider().
                    getIdentityProviderName(), sessionIndex);

            // Add AuthnContextClassRefs received with SAML2 Response to AuthenticationContext
            if (AS_RESPONSE.equalsIgnoreCase(context.getAuthenticatorProperties()
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.RESPONSE_AUTHN_CONTEXT_CLASS_REF))) {
                if (log.isDebugEnabled()) {
                    log.debug("AuthnContextClassRefs received with SAML response from the IdP '" + context
                            .getExternalIdP().getIdPName() + "' is passed to service provider.");
                }
                if (request.getSession().getAttribute(SSOConstants.AUTHN_CONTEXT_CLASS_REF) != null) {
                    AuthenticationContextProperty authenticationContextProperty =
                            new AuthenticationContextProperty(
                                    context.getExternalIdP().getIdPName(),
                                    SSOConstants.AUTHN_CONTEXT_CLASS_REF,
                                    request.getSession().getAttribute(SSOConstants.AUTHN_CONTEXT_CLASS_REF));

                    List<AuthenticationContextProperty> authenticationContextProperties;
                    if (context.getProperty(FrameworkConstants.AUTHENTICATION_CONTEXT_PROPERTIES) != null) {
                        authenticationContextProperties = (List<AuthenticationContextProperty>) context
                                .getProperty(FrameworkConstants.AUTHENTICATION_CONTEXT_PROPERTIES);
                    } else {
                        authenticationContextProperties = new ArrayList<>();
                        context.setProperty(FrameworkConstants.AUTHENTICATION_CONTEXT_PROPERTIES,
                                authenticationContextProperties);
                    }
                    authenticationContextProperties.add(authenticationContextProperty);
                }
            }

            AuthenticatedUser authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subject);
            authenticatedUser.setUserAttributes(receivedClaims);
            context.setSubject(authenticatedUser);
        } catch (SAMLSSOException e) {
            // whenever the code reaches here the subject identifier will be null. Therefore we can't pass
            // AuthenticatedUser object with the exception.
            throw new AuthenticationFailedException(e.getErrorCode(), e.getMessage(), e);
        } finally {
            // this is not needed - remove it.
            request.removeAttribute(AUTHENTICATION_CONTEXT);
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside getContextIdentifier()");
        }

        String identifier = request.getParameter("sessionDataKey");

        if (identifier == null) {
            identifier = request.getParameter("RelayState");

            if (identifier != null) {
                // TODO: SHOULD ensure that the value has not been tampered with by using a checksum,
                //  a pseudo-random value, or similar means.
                try {
                    return URLDecoder.decode(identifier, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    log.error("Exception while URL decoding the Relay State", e);
                }
            }
        }

        return identifier;
    }

    @Override
    public String getFriendlyName() {
        return SSOConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return SSOConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request,
                                         HttpServletResponse response, AuthenticationContext context)
            throws LogoutFailedException {

        boolean logoutEnabled = false;
        String logoutEnabledProp = context.getAuthenticatorProperties().get(
                IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED);

        logoutEnabled = Boolean.parseBoolean(logoutEnabledProp);

        if (logoutEnabled) {
            //send logout request to external idp
            String idpLogoutURL = context.getAuthenticatorProperties().get(
                    IdentityApplicationConstants.Authenticator.SAML2SSO.LOGOUT_REQ_URL);

            if (StringUtils.isBlank(idpLogoutURL)) {
                idpLogoutURL = context.getAuthenticatorProperties().get(
                        IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL);
            }

            if (StringUtils.isBlank(idpLogoutURL)) {
                throw new LogoutFailedException(
                        "Logout is enabled for the IdP but Logout URL is not configured");
            }

            AuthenticatorStateInfo stateInfo = context.getStateInfo();

            if (stateInfo instanceof StateInfo) {
                request.getSession().setAttribute(SSOConstants.LOGOUT_SESSION_INDEX,
                        ((StateInfo) stateInfo).getSessionIndex());
                request.getSession().setAttribute(SSOConstants.LOGOUT_USERNAME,
                        ((StateInfo) stateInfo).getSubject());
                request.getSession().setAttribute(SSOConstants.NAME_QUALIFIER,
                        ((StateInfo) stateInfo).getNameQualifier());
                request.getSession().setAttribute(SSOConstants.SP_NAME_QUALIFIER,
                        ((StateInfo) stateInfo).getSpNameQualifier());
            }

            try {
                SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
                saml2SSOManager.init(context.getTenantDomain(), context
                        .getAuthenticatorProperties(), context.getExternalIdP()
                        .getIdentityProvider());

                boolean isPost = false;
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

                String requestMethod = authenticatorProperties
                        .get(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD);

                if (requestMethod != null && requestMethod.trim().length() != 0) {
                    if ("POST".equalsIgnoreCase(requestMethod)) {
                        isPost = true;
                    } else if ("AS_REQUEST".equalsIgnoreCase(requestMethod)) {
                        isPost = context.getAuthenticationRequest().isPost();
                    }
                }

                if (isPost) {
                    sendPostRequest(request, response, true, idpLogoutURL, context);
                } else {
                    String logoutURL = saml2SSOManager.buildRequest(request, true, false,
                            idpLogoutURL, context);
                    response.sendRedirect(logoutURL);
                }
            } catch (IOException | SAMLSSOException e) {
                throw new LogoutFailedException(e.getMessage(), e);
            }
        } else {
            throw new UnsupportedOperationException();
        }
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request,
                                         HttpServletResponse response, AuthenticationContext context) {
        throw new UnsupportedOperationException();
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property spEntityId = new Property();
        spEntityId.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);
        spEntityId.setDisplayName("Service Provider Entity ID");
        spEntityId.setRequired(true);
        spEntityId.setDescription("Enter the service provider's entity identifier value");
        spEntityId.setType("string");
        spEntityId.setDisplayOrder(1);
        configProperties.add(spEntityId);

        Property nameIdFormat = new Property();
        nameIdFormat.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME_ID_TYPE);
        nameIdFormat.setDisplayName("NameID format");
        nameIdFormat.setRequired(true);
        nameIdFormat.setDescription("NameID format to be used in the SAML request");
        nameIdFormat.setType("string");
        nameIdFormat.setDisplayOrder(2);
        nameIdFormat.setDefaultValue(IdentityApplicationConstants.Authenticator.SAML2SSO.UNSPECIFIED_NAME_ID_FORMAT);
        configProperties.add(nameIdFormat);

        Property selectMode = new Property();
        selectMode.setName("selectMode");
        selectMode.setDisplayName("Select Mode");
        selectMode.setDescription("Select the input method for SAML configuration");
        selectMode.setType("string");
        selectMode.setOptions(new String[]{"Manual Configuration", "Metadata File Configuration"});
        selectMode.setDefaultValue("Manual Configuration");
        selectMode.setDisplayOrder(3);
        configProperties.add(selectMode);

        Property samlMetadata = new Property();
        samlMetadata.setName("meta_data_saml");
        samlMetadata.setDisplayName("SAML Metadata File");
        samlMetadata.setDescription("Base-64 encoded metadata file content for SAML configuration");
        samlMetadata.setType("string");
        samlMetadata.setDisplayOrder(4);
        configProperties.add(samlMetadata);

        Property idpEntityId = new Property();
        idpEntityId.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
        idpEntityId.setDisplayName("Identity Provider Entity ID");
        idpEntityId.setRequired(true);
        idpEntityId.setDescription("Enter identity provider's entity identifier value. This should be a valid URI/URL.");
        idpEntityId.setType("string");
        idpEntityId.setDisplayOrder(5);
        configProperties.add(idpEntityId);

        Property ssoUrl = new Property();
        ssoUrl.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL);
        ssoUrl.setDisplayName("SSO URL");
        ssoUrl.setRequired(true);
        ssoUrl.setDescription("Enter identity provider's SAML2 Web SSO URL value");
        ssoUrl.setType("string");
        ssoUrl.setDisplayOrder(6);
        configProperties.add(ssoUrl);

        Property acsUrl = new Property();
        acsUrl.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.ACS_URL);
        acsUrl.setDisplayName("ACS URL");
        acsUrl.setRequired(false);
        acsUrl.setDescription("Enter service provider's SAML2 ACS URL value");
        acsUrl.setType("string");
        acsUrl.setDisplayOrder(7);
        configProperties.add(acsUrl);

        Property authnReqSign = new Property();
        authnReqSign.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED);
        authnReqSign.setDisplayName("Enable Authentication Request Signing");
        authnReqSign.setRequired(false);
        authnReqSign.setDescription("Specifies if the SAML2 authentication request to the identity provider must be signed or not");
        authnReqSign.setType("boolean");
        authnReqSign.setDisplayOrder(8);
        configProperties.add(authnReqSign);

        Property assertionEncryption = new Property();
        assertionEncryption.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_ENCRYPTION);
        assertionEncryption.setDisplayName("Enable Assertion Encryption");
        assertionEncryption.setRequired(false);
        assertionEncryption.setDescription("Specify if SAMLAssertion element is encrypted");
        assertionEncryption.setType("boolean");
        assertionEncryption.setDisplayOrder(9);
        configProperties.add(assertionEncryption);

        Property assertionSigning = new Property();
        assertionSigning.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_SIGNING);
        assertionSigning.setDisplayName("Enable Assertion Signing");
        assertionSigning.setRequired(false);
        assertionSigning.setDescription("Specify if SAMLAssertion element is signed");
        assertionSigning.setType("boolean");
        assertionSigning.setDisplayOrder(10);
        configProperties.add(assertionSigning);

        Property enableLogout = new Property();
        enableLogout.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED);
        enableLogout.setDisplayName("Enable Logout");
        enableLogout.setRequired(false);
        enableLogout.setDescription("Specifies if logout/single Logout is enabled for this identity provider");
        enableLogout.setType("boolean");
        enableLogout.setDisplayOrder(11);
        configProperties.add(enableLogout);

        Property sloRequestAccepted = new Property();
        sloRequestAccepted.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_SLO_REQUEST_ACCEPTED);
        sloRequestAccepted.setDisplayName("Enable Logout Request Accepting");
        sloRequestAccepted.setRequired(false);
        sloRequestAccepted.setDescription("Specifies if single logout request from the identity provider is accepted");
        sloRequestAccepted.setType("boolean");
        sloRequestAccepted.setDisplayOrder(12);
        configProperties.add(sloRequestAccepted);

        Property logoutUrl = new Property();
        logoutUrl.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.LOGOUT_REQ_URL);
        logoutUrl.setDisplayName("Logout Url");
        logoutUrl.setRequired(false);
        logoutUrl.setDescription("Enter identity provider's logout URL value if it is different from the SSO Url");
        logoutUrl.setType("string");
        logoutUrl.setDisplayOrder(13);
        configProperties.add(logoutUrl);

        Property logoutReqSign = new Property();
        logoutReqSign.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED);
        logoutReqSign.setDisplayName("Enable Logout Request Signing");
        logoutReqSign.setRequired(false);
        logoutReqSign.setDescription("Specifies if SAML2 logout request to the identity provider must be signed or not");
        logoutReqSign.setType("boolean");
        logoutReqSign.setDisplayOrder(14);
        configProperties.add(logoutReqSign);

        Property authnResSign = new Property();
        authnResSign.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED);
        authnResSign.setDisplayName("Enable Authentication Response Signing");
        authnResSign.setRequired(false);
        authnResSign.setDescription("Specifies if SAML2 authentication response from the identity provider must be " +
                "signed or not");
        authnResSign.setType("boolean");
        authnResSign.setDisplayOrder(15);
        configProperties.add(authnResSign);

        Property enableArtifactBinding = new Property();
        enableArtifactBinding.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ARTIFACT_BINDING_ENABLED);
        enableArtifactBinding.setDisplayName(" Enable Artifact Binding");
        enableArtifactBinding.setRequired(false);
        enableArtifactBinding.setDescription("Specifies if SAML2 Artifact Binding is enabled from IDP");
        enableArtifactBinding.setType("boolean");
        enableArtifactBinding.setDisplayOrder(16);

        SubProperty artifactResolveUrl = new SubProperty();
        artifactResolveUrl.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.ARTIFACT_RESOLVE_URL);
        artifactResolveUrl.setDisplayName("Artifact Resolve Endpoint Url");
        artifactResolveUrl.setRequired(false);
        artifactResolveUrl.setDescription("Specify the Artifact Resolve Endpoint Url");
        artifactResolveUrl.setType("string");
        artifactResolveUrl.setDisplayOrder(17);

        SubProperty artifactResolveReqSign = new SubProperty();
        artifactResolveReqSign.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ARTIFACT_RESOLVE_REQ_SIGNED);
        artifactResolveReqSign.setDisplayName("Enable Artifact Resolve Request Signing");
        artifactResolveReqSign.setRequired(false);
        artifactResolveReqSign.setDescription(" Specifies if the SAML2 artifact resolve request to the identity provider must " +
                "be signed or not");
        artifactResolveReqSign.setType("boolean");
        artifactResolveReqSign.setDisplayOrder(18);

        SubProperty enableArtifactResSign = new SubProperty();
        enableArtifactResSign.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ARTIFACT_RESPONSE_SIGNED);
        enableArtifactResSign.setDisplayName("Enable Artifact Response Signing");
        enableArtifactResSign.setRequired(false);
        enableArtifactResSign.setDescription("Specifies if the SAML2 artifact response from the identity provider will be " +
                "signed or not");
        enableArtifactResSign.setType("boolean");
        enableArtifactResSign.setDisplayOrder(19);
        SubProperty[] enableArtifactBindingSubProps = new SubProperty[]{artifactResolveUrl, artifactResolveReqSign,
                enableArtifactResSign};
        enableArtifactBinding.setSubProperties(enableArtifactBindingSubProps);
        configProperties.add(enableArtifactBinding);

        Property signatureAlgo = new Property();
        signatureAlgo.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        signatureAlgo.setDisplayName("Signature Algorithm");
        signatureAlgo.setRequired(false);
        signatureAlgo.setDescription("Specifies the SignatureMethod Algorithm");
        signatureAlgo.setType("string");
        signatureAlgo.setDisplayOrder(20);

        List<String> signatureAlgoOptions = new ArrayList<>();
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.DSA_SHA1);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.ECDSA_SHA1);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.ECDSA_SHA256);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.ECDSA_SHA384);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.ECDSA_SHA512);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_MD5);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_RIPEMD160);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA256);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA384);
        signatureAlgoOptions.add(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA512);

        signatureAlgo.setOptions(signatureAlgoOptions.toArray(new String[0]));
        signatureAlgo.setDefaultValue(IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1);
        configProperties.add(signatureAlgo);

        Property digestAlgo = new Property();
        digestAlgo.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        digestAlgo.setDisplayName("Digest Algorithm");
        digestAlgo.setRequired(false);
        digestAlgo.setDescription("Specifies the DigestMethod Algorithm. Applicable only in POST Binding");
        digestAlgo.setType("string");
        digestAlgo.setDisplayOrder(21);

        List<String> digestAlgoOptions = new ArrayList<>();
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.MD5);
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.RIPEMD160);
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.SHA1);
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.SHA256);
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.SHA384);
        digestAlgoOptions.add(IdentityApplicationConstants.XML.DigestAlgorithm.SHA512);

        digestAlgo.setOptions(digestAlgoOptions.toArray(new String[0]));
        digestAlgo.setDefaultValue(IdentityApplicationConstants.XML.DigestAlgorithm.SHA1);
        configProperties.add(digestAlgo);

        Property attributeConsumeIndex = new Property();
        attributeConsumeIndex.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        attributeConsumeIndex.setDisplayName("Attribute Consuming Service Index");
        attributeConsumeIndex.setRequired(false);
        attributeConsumeIndex.setDescription("Specify the Attribute Consuming Service Index");
        attributeConsumeIndex.setType("string");
        attributeConsumeIndex.setDisplayOrder(22);
        configProperties.add(attributeConsumeIndex);

        Property forceAuthn = new Property();
        forceAuthn.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
        forceAuthn.setDisplayName("Enable Force Authentication");
        forceAuthn.setRequired(false);
        forceAuthn.setDescription("Enable force authentication or decide from the in coming request");
        forceAuthn.setType("string");
        forceAuthn.setDisplayOrder(23);
        forceAuthn.setOptions(new String[]{"yes", "no", "as_request"});
        forceAuthn.setDefaultValue("as_request");
        configProperties.add(forceAuthn);

        Property includeCert = new Property();
        includeCert.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT);
        includeCert.setDisplayName(" Include Public Certificate");
        includeCert.setRequired(false);
        includeCert.setDescription("Include Public Certificate in the the request");
        includeCert.setType("boolean");
        includeCert.setDisplayOrder(24);
        configProperties.add(includeCert);

        Property includeProtocolBinding = new Property();
        includeProtocolBinding.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
        includeProtocolBinding.setDisplayName(" Include Protocol Binding");
        includeProtocolBinding.setRequired(false);
        includeProtocolBinding.setDescription("Include ProtocolBinding in the request");
        includeProtocolBinding.setType("boolean");
        includeProtocolBinding.setDisplayOrder(25);
        configProperties.add(includeProtocolBinding);

        Property includeNameIdPolicy = new Property();
        includeNameIdPolicy.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);
        includeNameIdPolicy.setDisplayName(" Include NameID Policy");
        includeNameIdPolicy.setRequired(false);
        includeNameIdPolicy.setDescription("Include NameIDPolicy in the request");
        includeNameIdPolicy.setType("boolean");
        includeNameIdPolicy.setDisplayOrder(26);
        configProperties.add(includeNameIdPolicy);

        Property includeAuthnContext = new Property();
        includeAuthnContext.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);
        includeAuthnContext.setDisplayName(" Include Authentication Context");
        includeAuthnContext.setRequired(false);
        includeAuthnContext.setDescription("Include a new RequestedAuthnContext in the request, or decide from the incoming request");
        includeAuthnContext.setType("string");
        includeAuthnContext.setDisplayOrder(27);
        includeAuthnContext.setOptions(new String[]{"yes", "no", "as_request"});
        includeAuthnContext.setDefaultValue("yes");
        configProperties.add(includeAuthnContext);

        Property authnContextClass = new Property();
        authnContextClass.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_CLASS);
        authnContextClass.setDisplayName("Authentication Context Class");
        authnContextClass.setRequired(false);
        authnContextClass.setDescription(" Choose AuthnContextClassRef to be sent");
        authnContextClass.setType("string");

        List<String> authnContextOptions = new ArrayList<>();
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.AUTHENTICATED_TELEPHONY);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.IP);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.IP_PASSWORD);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.KERBEROS);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.MOBILE_ONE_FACTOR_CONTRACT);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.MOBILE_ONE_FACTOR_UNREGISTERED);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.MOBILE_TWO_FACTOR_CONTRACT);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.MOBILE_TWO_FACTOR_UNREGISTERED);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.NOMAD_TELEPHONY);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.PASSWORD);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.PASSWORD_PROTECTED_TRANSPORT);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.PERSONAL_TELEPHONY);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.PGP);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.PREVIOUS_SESSION);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.SECURE_REMOTE_PASSWORD);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.SMARTCARD);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.SMARTCARD_PKI);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.SOFTWARE_PKI);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.SPKI);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.TELEPHONY);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.TIME_SYNC_TOKEN);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.TLS_CLIENT);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.UNSPECIFIED);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.X509);
        authnContextOptions.add(IdentityApplicationConstants.SAML2.AuthnContextClass.XML_DSIG);
        authnContextOptions.add(IdentityApplicationConstants.Authenticator.SAML2SSO
                .CUSTOM_AUTHENTICATION_CONTEXT_CLASS_OPTION);

        authnContextClass.setOptions(authnContextOptions.toArray(new String[0]));
        authnContextClass.setDefaultValue(IdentityApplicationConstants.SAML2.AuthnContextClass.UNSPECIFIED);
        authnContextClass.setDisplayOrder(28);
        configProperties.add(authnContextClass);

        Property customAuthnContextClass = new Property();
        customAuthnContextClass.setName(IdentityApplicationConstants.Authenticator.SAML2SSO
                .ATTRIBUTE_CUSTOM_AUTHENTICATION_CONTEXT_CLASS);
        customAuthnContextClass.setDisplayName(null);
        customAuthnContextClass.setRequired(false);
        customAuthnContextClass.setDescription("Custom AuthnContextClassRef to be sent");
        customAuthnContextClass.setType("string");
        customAuthnContextClass.setDisplayOrder(29);
        configProperties.add(customAuthnContextClass);

        Property authnContextComparison = new Property();
        authnContextComparison.setName(IdentityApplicationConstants.Authenticator.SAML2SSO
                .AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);
        authnContextComparison.setDisplayName("Authentication Context Comparison Level");
        authnContextComparison.setRequired(false);
        authnContextComparison.setDescription("Choose RequestedAuthnContext Comparison to be sent");
        authnContextComparison.setType("string");
        authnContextComparison.setDisplayOrder(30);
        authnContextComparison.setOptions(new String[]{"Exact", "Mininum", "Maximum", "Better"});
        authnContextComparison.setDefaultValue("Exact");
        configProperties.add(authnContextComparison);

        Property userIdLocation = new Property();
        userIdLocation.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS);
        userIdLocation.setDisplayName("SAML2 Web SSO User ID Location");
        userIdLocation.setRequired(false);
        userIdLocation.setDescription("Specifies the location to find the user identifier in the SAML2 assertion");
        userIdLocation.setType("boolean");
        userIdLocation.setDisplayOrder(31);
        userIdLocation.setDefaultValue("false");
        configProperties.add(userIdLocation);

        Property httpBinding = new Property();
        httpBinding.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD);
        httpBinding.setDisplayName("HTTP Binding");
        httpBinding.setRequired(false);
        httpBinding.setDescription("Choose the HTTP Binding or decide from incoming request");
        httpBinding.setType("string");
        httpBinding.setDisplayOrder(32);
        httpBinding.setOptions(new String[]{"redirect", "post", "as_request"});
        httpBinding.setDefaultValue("redirect");
        configProperties.add(httpBinding);

        Property resAuthnContextClass = new Property();
        resAuthnContextClass.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.RESPONSE_AUTHN_CONTEXT_CLASS_REF);
        resAuthnContextClass.setDisplayName("Response Authentication Context Class");
        resAuthnContextClass.setRequired(false);
        resAuthnContextClass.setDescription("Choose the AuthnContextClassRef sent back to the service provider");
        resAuthnContextClass.setType("string");
        resAuthnContextClass.setDisplayOrder(33);
        resAuthnContextClass.setOptions(new String[]{"default", "as_response"});
        resAuthnContextClass.setDefaultValue("default");
        configProperties.add(resAuthnContextClass);

        Property queryParams = new Property();
        queryParams.setName("commonAuthQueryParams");
        queryParams.setDisplayName("Additional Query Parameters");
        queryParams.setRequired(false);
        queryParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        queryParams.setType("string");
        queryParams.setDisplayOrder(34);
        configProperties.add(queryParams);

        Property signatureAlgorithmPost = new Property();
        signatureAlgorithmPost.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM_POST);
        signatureAlgorithmPost.setDisplayName(null);
        signatureAlgorithmPost.setRequired(false);
        signatureAlgorithmPost.setDescription(null);
        signatureAlgorithmPost.setType("string");
        signatureAlgorithmPost.setDisplayOrder(0);
        configProperties.add(signatureAlgorithmPost);

        return configProperties;
    }

    private void sendPostRequest(HttpServletRequest request, HttpServletResponse response,
                                 boolean isLogout, String loginPage, AuthenticationContext context)
            throws SAMLSSOException {

        SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
        saml2SSOManager.init(context.getTenantDomain(), context.getAuthenticatorProperties(),
                context.getExternalIdP().getIdentityProvider());

        if (!(saml2SSOManager instanceof DefaultSAML2SSOManager)) {
            throw new SAMLSSOException(ErrorMessages.HTTP_POST_NOT_SUPPORTED.getCode(),
                    ErrorMessages.HTTP_POST_NOT_SUPPORTED.getMessage());
        }

        String encodedRequest = ((DefaultSAML2SSOManager) saml2SSOManager).buildPostRequest(
                request, isLogout, false, loginPage, context);
        String relayState = context.getContextIdentifier();

        Map<String, String> reqParamMap = getAdditionalRequestParams(request, context);
        String postPageInputs = buildPostPageInputs(encodedRequest, relayState, reqParamMap);
        printPostPage(response, loginPage, postPageInputs);
    }

    private SAML2SSOManager getSAML2SSOManagerInstance() throws SAMLSSOException {

        String managerClassName = getAuthenticatorConfig().getParameterMap()
                .get(SSOConstants.ServerConfig.SAML2_SSO_MANAGER);
        if (managerClassName != null) {
            try {
                Class clazz = Class.forName(managerClassName);
                return (SAML2SSOManager) clazz.newInstance();
            } catch (ClassNotFoundException e) {
                throw new SAMLSSOException(ErrorMessages.CLASS_NOT_FOUND_EXCEPTION.getCode(), e.getMessage(), e);
            } catch (InstantiationException e) {
                throw new SAMLSSOException(ErrorMessages.INSTANTIATION_FAILED.getCode(), e.getMessage(), e);
            } catch (IllegalAccessException e) {
                throw new SAMLSSOException(ErrorMessages.ILLEGAL_ACCESS.getCode(), e.getMessage(), e);
            }
        } else {
            return new DefaultSAML2SSOManager();
        }
    }

    private String buildPostPageInputs(String encodedRequest, String relayState,
                                       Map<String, String> reqParamMap) throws SAMLSSOException {
        StringBuilder hiddenInputBuilder = new StringBuilder("");
        hiddenInputBuilder.append("<input type='hidden' name='SAMLRequest' value='")
                .append(encodedRequest).append("'>");

        if (relayState != null) {
            hiddenInputBuilder.append("<input type='hidden' name='RelayState' value='")
                    .append(relayState).append("'>");
        }

        for (Map.Entry<String, String> reqParam : reqParamMap.entrySet()) {
            String paramName = reqParam.getKey();
            String paramValue;
            try {
                paramValue = URLDecoder.decode(reqParam.getValue(), StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e) {
                throw new SAMLSSOException("Error while building POST request.", e);
            }
            hiddenInputBuilder.append("<input type='hidden' name='").append(Encode.forHtmlAttribute(paramName))
                    .append("' value='").append(Encode.forHtmlAttribute(paramValue) ).append("'>");
        }

        return hiddenInputBuilder.toString();
    }

    private Map<String, String> getAdditionalRequestParams(HttpServletRequest request,
                                                           AuthenticationContext context) {
        Map<String, String> reqParamMap = new HashMap<>();
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        if (authenticatorProperties != null) {
            String queryString = authenticatorProperties.get(FrameworkConstants.QUERY_PARAMS);
            if (queryString != null) {
                reqParamMap = SSOUtils.getQueryMap(queryString);
            }
        }

        String fidp = request.getParameter("domain");
        if (fidp != null) {
            reqParamMap.put("fidp", Encode.forHtmlAttribute(fidp));
        }

        return reqParamMap;
    }

    private void printPostPage(HttpServletResponse response, String url, String postPageInputs)
            throws SAMLSSOException {

        try {
            String postPage = SAMLSSOAuthenticatorServiceComponent.getPostPage();
            response.setContentType("text/html; charset=UTF-8");
            if (postPage != null) {
                String pageWithURL = postPage.replace("$url", Encode.forHtmlAttribute(url));
                String finalPage = pageWithURL.replace("<!--$params-->", postPageInputs);
                PrintWriter out = response.getWriter();
                out.print(finalPage);

                if (log.isDebugEnabled()) {
                    log.debug("HTTP-POST page: " + finalPage);
                }
            } else {
                PrintWriter out = response.getWriter();
                out.println("<html>");
                out.println("<body>");
                out.println("<p>You are now redirected to " + Encode.forHtml(url));
                out.println(" If the redirection fails, please click the post button.</p>");
                out.println("<form method='post' action='" + Encode.forHtmlAttribute(url) + "'>");
                out.println("<p>");
                out.println(postPageInputs);
                out.println("<button type='submit'>POST</button>");
                out.println("</p>");
                out.println("</form>");
                out.println("<script type='text/javascript'>");
                out.println("document.forms[0].submit();");
                out.println("</script>");
                out.println("</body>");
                out.println("</html>");
            }
        } catch (Exception e) {
            throw new SAMLSSOException(ErrorMessages.IO_ERROR.getCode(), "Error while sending POST request", e);
        }
    }
}
