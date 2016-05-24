package org.wso2.carbon.identity.application.authenticator.samlsso;


import org.wso2.carbon.identity.application.authentication.framework.processor.request.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.processor.request.LocalAuthenticationRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLFederatedRequest extends LocalAuthenticationRequest{

    private String samlResponse ;

    protected SAMLFederatedRequest(
            SAMLFederatedRequestBuilder builder) {
        super(builder);
        this.samlResponse = builder.samlResponse ;
    }

    public String getSamlResponse() {
        return samlResponse;
    }

    public static class SAMLFederatedRequestBuilder extends LocalAuthenticationRequest.LocalAuthenticationRequestBuilder {
        private String samlResponse ;

        public SAMLFederatedRequestBuilder(HttpServletRequest request,
                                           HttpServletResponse response) {
            super(request, response);
        }

        public SAMLFederatedRequestBuilder(String samlResponse) {
            this.samlResponse = samlResponse;
        }

        public LocalAuthenticationRequestBuilder setSAMLResponse(String samlResponse) {
            this.samlResponse = samlResponse;
            return this;
        }
    }

    public static class SAMLFederatedRequestConstants extends LocalAuthenticationRequest.LocalAuthenticationRequestConstants {
        public static final String SAML_RESPONSE = "SAMLResponse";
        public static final String RELAY_STATE = "RelayState";
    }

}
