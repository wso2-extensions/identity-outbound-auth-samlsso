package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.wso2.carbon.identity.application.authentication.framework.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.IdentityRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Enumeration;

public class SAMLFederatedRequestFactory extends HttpIdentityRequestFactory{
    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        return true ;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(IdentityRequest.IdentityRequestBuilder builder, HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        super.create(builder, request, response);
        SAMLFederatedRequest.SAMLFederatedRequestBuilder samlFederatedRequestBuilder = (SAMLFederatedRequest.SAMLFederatedRequestBuilder)builder ;

        samlFederatedRequestBuilder.setSAMLResponse(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.SAML_RESPONSE));
        samlFederatedRequestBuilder.setRequestDataKey(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.RELAY_STATE));
        return builder ;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception,
                                                                            HttpServletRequest request,
                                                                            HttpServletResponse response) {
        return super.handleException(exception, request, response);
    }

    @Override
    public String getName() {
        return super.getName();
    }

    @Override
    public int getPriority() {
        return super.getPriority();
    }
}
