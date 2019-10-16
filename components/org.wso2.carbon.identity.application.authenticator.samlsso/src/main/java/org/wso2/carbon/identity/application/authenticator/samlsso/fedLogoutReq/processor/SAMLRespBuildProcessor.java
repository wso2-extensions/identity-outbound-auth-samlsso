package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.processor;


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.*;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;

public class SAMLRespBuildProcessor extends IdentityProcessor {


    @Override
    public SAMLLogoutResponse.SAMLLogoutResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        String sessionDataKey = identityRequest.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        IdentityMessageContext context = InboundUtil.getContextFromCache(sessionDataKey);
        SAMLMessageContext samlMessageContext = (SAMLMessageContext)context;

        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = new SAMLLogoutResponse.SAMLLogoutResponseBuilder(samlMessageContext);
        builder.setResponse(samlMessageContext.getResponse());
        builder.setAcsUrl(samlMessageContext.getAcsUrl());
        return builder;
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
    public boolean canHandle(IdentityRequest identityRequest) {

        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            if (context.getRequest() instanceof SAMLLogoutRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getPriority() {
        return 1;
    }
}
