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
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_ARTIFACT_ID;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_RESP;

public class SAMLSSOAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8097512332218044859L;
    public static final String AS_REQUEST = "AS_REQUEST";
    public static final String AUTHENTICATION_CONTEXT = "AUTHENTICATION_CONTEXT";

    private static final String AS_RESPONSE = "AS_RESPONSE";

    private static Log log = LogFactory.getLog(SAMLSSOAuthenticator.class);

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
        String ssoUrl = "";
        boolean isPost = false;

        try {
            String requestMethod = authenticatorProperties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD);

            if (requestMethod != null && requestMethod.trim().length() != 0) {
                if (SSOConstants.POST.equalsIgnoreCase(requestMethod)) {
                    isPost = true;
                } else if (SSOConstants.REDIRECT.equalsIgnoreCase(requestMethod)) {
                    isPost = false;
                } else if (AS_REQUEST.equalsIgnoreCase(requestMethod)) {
                    isPost = context.getAuthenticationRequest().isPost();
                }
            } else {
                isPost = false;
            }

            // Resolves dynamic query parameters from "Additional Query Parameters".
            resolveDynamicParameter(request, context);

            if (isPost) {
                sendPostRequest(request, response, false, false, idpURL, context);
                return;

            } else {
                SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
                saml2SSOManager.init(context.getTenantDomain(), context.getAuthenticatorProperties(),
                        context.getExternalIdP().getIdentityProvider());
                ssoUrl = saml2SSOManager.buildRequest(request, false, false, idpURL, context);
                generateAuthenticationRequest(request, response, ssoUrl, authenticatorProperties);

            }
        } catch (SAMLSSOException | UnsupportedEncodingException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
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
        }
        return resolvedQueryParamValue;
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
            throw new AuthenticationFailedException(
                    "Error while sending the redirect to federated SAML IdP", e);
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
                throw new SAMLSSOException("Cannot find federated User Identifier");
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
            throw new AuthenticationFailedException(e.getMessage(), e);
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
                // TODO: SHOULD ensure that the value has not been tampered with by using a checksum, a pseudo-random value, or similar means.
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

        if (logoutEnabledProp != null && "true".equalsIgnoreCase(logoutEnabledProp)) {
            logoutEnabled = true;
        }

        if (logoutEnabled) {
            //send logout request to external idp
            String idpLogoutURL = context.getAuthenticatorProperties().get(
                    IdentityApplicationConstants.Authenticator.SAML2SSO.LOGOUT_REQ_URL);

            if (idpLogoutURL == null || idpLogoutURL.trim().length() == 0) {
                idpLogoutURL = context.getAuthenticatorProperties().get(
                        IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL);
            }

            if (idpLogoutURL == null || idpLogoutURL.trim().length() == 0) {
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
                    } else if ("REDIRECT".equalsIgnoreCase(requestMethod)) {
                        isPost = false;
                    } else if ("AS_REQUEST".equalsIgnoreCase(requestMethod)) {
                        isPost = context.getAuthenticationRequest().isPost();
                    }
                } else {
                    isPost = false;
                }

                if (isPost) {
                    sendPostRequest(request, response, true, false, idpLogoutURL, context);
                } else {
                    String logoutURL = saml2SSOManager.buildRequest(request, true, false,
                            idpLogoutURL, context);
                    response.sendRedirect(logoutURL);
                }
            } catch (IOException e) {
                throw new LogoutFailedException(e.getMessage(), e);
            } catch (SAMLSSOException e) {
                throw new LogoutFailedException(e.getMessage(), e);
            }
        } else {
            // Fixed issue #5707 - Proper error message is needed when logout is not supported with SAML2 Federated Authenticator
            throw new UnsupportedOperationException("Logout operation not supported with SAML2 Federated Authenticator");
        }
    }

    @Override
    protected void processLogoutResponse(HttpServletRequest request,
                                         HttpServletResponse response, AuthenticationContext context)
            throws LogoutFailedException {
        throw new UnsupportedOperationException();
    }

    private void sendPostRequest(HttpServletRequest request, HttpServletResponse response,
                                 boolean isLogout, boolean isPassive,
                                 String loginPage, AuthenticationContext context) throws SAMLSSOException {

        SAML2SSOManager saml2SSOManager = getSAML2SSOManagerInstance();
        saml2SSOManager.init(context.getTenantDomain(), context.getAuthenticatorProperties(),
                context.getExternalIdP().getIdentityProvider());

        if (!(saml2SSOManager instanceof DefaultSAML2SSOManager)) {
            throw new SAMLSSOException("HTTP-POST is not supported");
        }

        String encodedRequest = ((DefaultSAML2SSOManager) saml2SSOManager).buildPostRequest(
                request, isLogout, isPassive, loginPage, context);
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
                throw new SAMLSSOException(e.getMessage(), e);
            } catch (InstantiationException e) {
                throw new SAMLSSOException(e.getMessage(), e);
            } catch (IllegalAccessException e) {
                throw new SAMLSSOException(e.getMessage(), e);
            }
        } else {
            return new DefaultSAML2SSOManager();
        }
    }

    private String buildPostPageInputs(String encodedRequest, String relayState,
                                       Map<String, String> reqParamMap) {
        StringBuilder hiddenInputBuilder = new StringBuilder("");
        hiddenInputBuilder.append("<input type='hidden' name='SAMLRequest' value='")
                .append(encodedRequest).append("'>");

        if (relayState != null) {
            hiddenInputBuilder.append("<input type='hidden' name='RelayState' value='")
                    .append(relayState).append("'>");
        }

        for (Map.Entry<String, String> reqParam : reqParamMap.entrySet()) {
            String paramName = reqParam.getKey();
            String paramValue = reqParam.getValue();
            hiddenInputBuilder.append("<input type='hidden' name='").append(paramName)
                    .append("' value='").append(paramValue).append("'>");
        }

        return hiddenInputBuilder.toString();
    }

    private Map<String, String> getAdditionalRequestParams(HttpServletRequest request,
                                                           AuthenticationContext context) {
        Map<String, String> reqParamMap = new HashMap<String, String>();
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
            throw new SAMLSSOException("Error while sending POST request", e);
        }
    }
}
