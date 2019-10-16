package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.response;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context.SAMLMessageContext;


public class SAMLLogoutResponse extends IdentityResponse {


    protected SAMLMessageContext context;
    protected String response;
    protected String acsUrl;
    protected String relayState;


    protected SAMLLogoutResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.context = ((SAMLLogoutResponseBuilder) builder).context;
        this.response = ((SAMLLogoutResponseBuilder) builder).response;
        this.acsUrl = ((SAMLLogoutResponseBuilder) builder).acsUrl;
        this.relayState = ((SAMLLogoutResponseBuilder) builder).relayState;

    }

    public String getResponse() {
        return response;
    }
    public String getAcsUrl() {
        return acsUrl;
    }
    public String getRelayState() { return relayState; }

    public static class SAMLLogoutResponseBuilder extends IdentityResponseBuilder {

        protected SAMLMessageContext context;
        protected String response;
        protected String acsUrl;
        protected String relayState;

        public SAMLLogoutResponseBuilder(SAMLMessageContext context) {
            this.context = context;
        }

        @Override
        public SAMLLogoutResponse build() {
            return new SAMLLogoutResponse(this);
        }

        public SAMLLogoutResponseBuilder setResponse(String response) {

            this.response = response;
            return this;
        }

        public SAMLLogoutResponseBuilder setAcsUrl(String acsUrl) {

            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLLogoutResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }
    }

}
