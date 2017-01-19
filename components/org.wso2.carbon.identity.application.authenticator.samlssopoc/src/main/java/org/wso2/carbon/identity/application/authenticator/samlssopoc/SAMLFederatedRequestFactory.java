package org.wso2.carbon.identity.application.authenticator.samlssopoc;

import org.wso2.carbon.identity.framework.FrameworkClientException;
import org.wso2.carbon.identity.framework.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.framework.HttpIdentityResponse;
import org.wso2.carbon.identity.framework.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLFederatedRequestFactory <T extends SAMLFederatedRequest.SAMLFederatedRequestBuilder> extends HttpIdentityRequestFactory<T>{
    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        String samlResponse = request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.SAML_RESPONSE);
        if(samlResponse != null) {
            return true;
        }
        return false ;
    }

    @Override
    public void create(T builder, HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        super.create(builder, request, response);

        SAMLFederatedRequest.SAMLFederatedRequestBuilder samlFederatedRequestBuilder = (SAMLFederatedRequest.SAMLFederatedRequestBuilder)builder ;

        samlFederatedRequestBuilder.setSAMLResponse(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.SAML_RESPONSE));
        samlFederatedRequestBuilder.setRequestDataKey(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.RELAY_STATE));
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        SAMLFederatedRequest.SAMLFederatedRequestBuilder samlFederatedRequestBuilder = new SAMLFederatedRequest.SAMLFederatedRequestBuilder(request, response);
        create((T)samlFederatedRequestBuilder, request, response);

        return samlFederatedRequestBuilder ;
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
