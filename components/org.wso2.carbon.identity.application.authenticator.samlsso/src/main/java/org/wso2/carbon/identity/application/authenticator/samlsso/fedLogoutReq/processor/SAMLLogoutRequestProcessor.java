package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.processor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.*;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.Validators.LogoutRequestValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.dao.SessionDetailsDAO;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.exception.SAMLIdentityException;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.util.SAMLFedLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED;


public class SAMLLogoutRequestProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(SAMLLogoutRequestProcessor.class);


    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if(identityRequest instanceof SAMLLogoutRequest) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkLogoutResponse.FrameworkLogoutResponseBuilder process(IdentityRequest identityRequest) throws SAMLIdentityException {

        SAMLMessageContext context = new SAMLMessageContext(identityRequest, new HashMap<String, String>());
        try {

            XMLObject samlRequest;

            if (context.getSAMLLogoutRequest().isPost()) {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decodeForPost(context.getSamlRequest()));
            } else {
                samlRequest = SSOUtils.unmarshall(SSOUtils.decode(context.getSamlRequest()));
            }

            LogoutRequest logoutRequest;
            if (samlRequest instanceof LogoutRequest) {
                logoutRequest = (LogoutRequest) samlRequest;
                context.setLogoutReq(logoutRequest);
            }else {
                context.setValidStatus(false);
                throw new SAMLIdentityException("Invalid Single Logout SAML Request");
            }

            //validate the logout request
            LogoutRequestValidator logoutRequestValidator = new LogoutRequestValidator(context);
            logoutRequestValidator.validate();

            if (StringUtils.isBlank(context.getSAMLLogoutRequest().getIdpSessionIndex())) {
                context.setValidStatus(false);
                throw new SAMLIdentityException("Session Index should be present in the Logout Request");
            }

            //get session details relevant to idp session index
            SessionDetailsDAO sessionDetailsDAO = new SessionDetailsDAO();
            Map<String, String> sessionDetails = sessionDetailsDAO.getSessionDetails(context.getSAMLLogoutRequest().getIdpSessionIndex());

            if (sessionDetails != null) {

                IdentityProvider identityProvider = IdentityProviderManager.getInstance().getIdPById(sessionDetails.get("idpID"),
                    (context.getSAMLLogoutRequest().getTenantDomain()));
                Map<String, String> fedIdpConfigs = SAMLFedLogoutUtil.getFederatedIdpConfigs(identityProvider);
                context.setSessionID(sessionDetails.get("sessionID"));
                context.setFederatedIdp(identityProvider);
                context.setFedIdpConfigs(fedIdpConfigs);
            }

            // Validate signature of the logout request.
            if ((context.getFedIdpConfigs().get(IS_LOGOUT_REQ_SIGNED)).equals("true")) {
                if (!SAMLFedLogoutUtil.validateLogoutRequestSignature(logoutRequest, context)) {
                    String errorMessage = "Signature validation for Logout Request failed";
                    log.error(errorMessage);
                    context.setValidStatus(false);
                    String errorResponse = SAMLFedLogoutUtil.buildErrorResponse(context, logoutRequest.getID(),
                        SAMLConstants.StatusCodes.REQUESTOR_ERROR, errorMessage);
                    throw new SAMLIdentityException(errorMessage, errorResponse, logoutRequest.getDestination(), context.getRelayState());
                }
            }

            LogoutResponse logoutResp = SAMLFedLogoutUtil.buildResponse(context, logoutRequest.getID(),
                SAMLConstants.StatusCodes.SUCCESS_CODE, null);
            context.setResponse(SSOUtils.encode(SSOUtils.marshall(logoutResp)));
            context.setAcsUrl(logoutResp.getDestination());

        } catch (IdentityProviderManagementException e) {
            throw new SAMLIdentityException("cannot retrieve the identity provider", e);
        }catch (SAMLSSOException e){
            throw new SAMLIdentityException("Error occurred while building the logout response");
        }catch (IdentityException e){
            throw new SAMLIdentityException("Error occurred while validating the logout request");
        }

        return buildResponseForFrameworkLogout(context);
    }

    protected FrameworkLogoutResponse.FrameworkLogoutResponseBuilder buildResponseForFrameworkLogout(SAMLMessageContext context) {

        IdentityRequest identityRequest = context.getRequest();
        Map<String, String[]> parameterMap = identityRequest.getParameterMap();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        Set<Map.Entry<String,String>> headers = new HashMap(identityRequest.getHeaderMap()).entrySet();
        for (Map.Entry<String,String> header : headers) {
            authenticationRequest.addHeader(header.getKey(), header.getValue());
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
        responseBuilder.setRelyingParty(getRelyingPartyId(context));
        responseBuilder.setAuthType(getType(context));
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
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

    @Override
    public String getType(IdentityMessageContext context) {
        return SAMLConstants.CLAIM_TYPE_SAML_SSO;
    }




}
