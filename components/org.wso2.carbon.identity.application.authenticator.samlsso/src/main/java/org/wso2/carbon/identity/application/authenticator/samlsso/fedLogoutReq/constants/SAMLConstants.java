package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants;

public class SAMLConstants {

        public static final String SAML_REQUEST = "SAMLRequest";
        public static final java.lang.String CLAIM_TYPE_SAML_SSO = "samlsso";
        public static final String ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        public static final String RELAY_STATE = "RelayState";

    public static class StatusCodes {

        public static final String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public static final String REQUESTOR_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public static final String VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

    }
}
