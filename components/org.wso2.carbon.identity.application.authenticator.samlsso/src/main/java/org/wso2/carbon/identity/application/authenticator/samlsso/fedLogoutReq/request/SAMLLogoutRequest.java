package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLLogoutRequest extends IdentityRequest {


    private String idpSessionIndex;
    private String subject;
    private boolean isPost;

    protected SAMLLogoutRequest(SAMLLogoutRequestBuilder builder) throws FrameworkClientException {
        super(builder);
        this.idpSessionIndex = builder.idpSessionIndex;
        this.subject = builder.subject;
        this.isPost = builder.isPost;
    }

    public boolean isPost() {
        return isPost;
    }

    public String getIdpSessionIndex() {
        return idpSessionIndex;
    }

    public String getSubject() { return subject; }

    public static class SAMLLogoutRequestBuilder extends IdentityRequestBuilder{

        private boolean isPost;
        private String idpSessionIndex;
        private String subject;

        public SAMLLogoutRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }


        public SAMLLogoutRequestBuilder isPost(boolean isPost){
            this.isPost = isPost;
            return this;
        }

        public SAMLLogoutRequestBuilder setIdpSessionIndex(String idpSessionIndex) {
            this.idpSessionIndex = idpSessionIndex;
            return this;
        }

        public SAMLLogoutRequestBuilder setSubject(String subject) {
            this.subject = subject;
            return this;
        }

        @Override
        public SAMLLogoutRequest build() throws FrameworkClientException {
            return new SAMLLogoutRequest(this);
        }
    }



//    public SAMLLogoutRequest(SAMLLogoutInitRequestBuilder builder) throws FrameworkClientException {
//
//        super((SAMLIdentityRequestBuilder)builder);
//        this.logoutReqID = ((SAMLLogoutInitRequestBuilder)builder).logoutReqID;
//        this.idpSessionID=((SAMLLogoutInitRequestBuilder)builder).idpSessionID;
//    }
//
//    public static SAMLLogoutInitRequestBuilder extends SAMLIdentityRequestBuilder {
//
//        protected String logoutReqID;
//        protected String idpSessionID;
//
//        public SAMLLogoutInitRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
//            super(request, response);
//
//        }
//        public String setLogoutRequestID(String logoutReqID) {
//            this.logoutReqID = logoutReqID;
//            return this;
//        }
//
//        public void setIdpSessionID(String idpSessionID) {
//            this.idpSessionID = idpSessionID;
//        }
//
//        @Override
//        public SAMLLogoutRequest build() throws FrameworkClientException {
//            return new SAMLLogoutRequest(this);
//        }
//    }

}
