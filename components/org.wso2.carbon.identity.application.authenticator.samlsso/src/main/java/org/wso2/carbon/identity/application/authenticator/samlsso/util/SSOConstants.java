/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.samlsso.util;

import java.util.regex.Pattern;

public class SSOConstants {

    public static final String AUTHENTICATOR_NAME = "SAMLSSOAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "samlsso";

    public static final String HTTP_POST_PARAM_SAML2_AUTH_REQ = "SAMLRequest";
    public static final String HTTP_POST_PARAM_SAML2_RESP = "SAMLResponse";
    public static final String HTTP_POST_PARAM_SAML2_ARTIFACT_ID = "SAMLart";
    public static final String IDP_SESSION = "IdPSession";
    public static final String RELAY_STATE = "RelayState";

    public static final String HTTP_POST = "POST";
    public static final String POST = "POST";
    public static final String REDIRECT = "REDIRECT";

	public static final String SERVLET_REQ_ATTR_AUTHENTICATION_CONTEXT = "authenticationContext";

    public static final String SP_NAME_QUALIFIER = "spNameQualifier";
    public static final String NAME_QUALIFIER = "nameQualifier";
    public static final String LOGOUT_USERNAME = "logoutUsername";
    public static final String LOGOUT_SESSION_INDEX = "logoutSessionIndex";
    public static final String AUTHN_CONTEXT_CLASS_REF = "AuthnContextClassRef";
    public static final String NAME_ID_FORMAT = "nameIdFormat";
    public static final String ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    public static final String SOAP_ACTION_PARAM_KEY = "SOAPAction";
    public static final String ACCEPT_PARAM_KEY = "Accept";
    public static final String CONTENT_TYPE_PARAM_KEY = "Content-Type";
    public static final String PRAGMA_PARAM_KEY = "Pragma";
    public static final String CACHE_CONTROL_PARAM_KEY = "Cache-Control";

    public static final String SECURITY_KEYSTORE_LOCATION = "Security.KeyStore.Location";
    public static final String SECURITY_KEYSTORE_TYPE = "Security.KeyStore.Type";

    public static final String SAML_SLO_URL = "identity/saml/slo";
    public static final Pattern SAML_SLO_ENDPOINT_URL_PATTERN = Pattern.compile("(.*)/identity/saml/slo/?");

    public class StatusCodes {
        private StatusCodes() {

        }

        public static final String IDENTITY_PROVIDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        public static final String NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        public static final String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public static final String REQUESTOR_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public static final String VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";

    }

    public class ServerConfig {
        private ServerConfig() {

        }

        public static final String KEY_ALIAS = "Security.KeyStore.KeyAlias";
        public static final String KEY_PASSWORD = "Security.KeyStore.KeyPassword";

        public static final String SAML2_SSO_MANAGER = "SAML2SSOManager";
        public static final String SAML_SSO_ACS_URL = "SAMLSSOAssertionConsumerUrl";

        public static final String HTTPS_PROXY_HOST = "HTTPS_PROXY_HOST";
        public static final String HTTPS_PROXY_PORT = "HTTPS_PROXY_PORT";
    }

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String OUTBOUND_AUTH_SAMLSSO_SERVICE = "outbound-auth-samlsso";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-outbound-auth-samlsso-response";
            public static final String INITIATE_OUTBOUND_AUTH_REQUEST = "initiate-outbound-auth-samlsso-request";
        }

        /**
         * Define input keys for diagnostic logs.
         */
        public  static class InputKeys {

            public static final String IS_POST = "is post";
        }
    }
}
