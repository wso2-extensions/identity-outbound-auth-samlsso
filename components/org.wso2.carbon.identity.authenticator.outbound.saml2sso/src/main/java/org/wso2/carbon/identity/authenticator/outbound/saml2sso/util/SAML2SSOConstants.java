/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.util;

public class SAML2SSOConstants {

    public static final String AUTHENTICATOR_NAME = "SAML2SSOAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "SAML2 Web SSO Federated Authenticator";
    public static final String INBOUND_AUTHN_REQUEST = "InboundAuthnRequest" ;
    public static final String ACS_URL = "AssertionConsumerURL";
    public static final String SP_NAME_QUALIFIER = "spNameQualifier";
    public static final String NAME_QUALIFIER = "nameQualifier";
    public static final String LOGOUT_USERNAME = "logoutUsername";
    public static final String LOGOUT_SESSION_INDEX = "logoutSessionIndex";

    public static final String SAML_REQUEST = "SAMLRequest";
    public static final String SAML_RESPONSE = "SAMLResponse";
    public static final String RELAY_STATE = "RelayState";
    public static final String AS_REQUEST = "AS_REQUEST";
    public static final String REQUEST_BINDING = "RequestBinding";
    public static final String POST = "POST";
    public static final String GET = "GET";
    public static final String FORCE = "Force";
    public static final String PASSIVE = "Passive";
    public static final String SAML2_SSO_URL = "SAML2SSOUrl";
    public static final String AUTHN_REQUEST_SIGNED = "AuthnRequestSigned";
    public static final String AUTHN_RESPONSE_SIGNED = "AuthnResponseSigned";
    public static final String AUTHN_RESPONSE_ENCRYPTED = "AuthnResponseEncrypted";
    public static final String SIGNATURE_ALGO = "SignatureAlgo";
    public static final String DIGEST_ALGO = "DigestAlgo";
}
