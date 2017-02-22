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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.response;

import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;

// can we extend this from SAML2SSORedirectRequestResponse ?
public class SAML2SSOPostRequestResponse extends GatewayResponse {

    protected String saml2SSOUrl;
    protected RequestAbstractType samlRequest;
    protected String relayState;
    protected boolean isAuthnRequestSigned;
    protected X509Credential idPCredential;
    protected String sigAlg;
    protected String digestAlg;

    protected SAML2SSOPostRequestResponse(SAML2SSOPostRequestResponseBuilder builder) {
        super(builder);
        saml2SSOUrl = builder.saml2SSOUrl;
        samlRequest = builder.samlRequest;
        relayState = builder.relayState;
        isAuthnRequestSigned = builder.isAuthnRequestSigned;
        idPCredential = builder.idPCredential;
        sigAlg = builder.sigAlg;
        digestAlg = builder.digestAlg;
    }

    public String getSaml2SSOUrl() {
        return saml2SSOUrl;
    }

    public RequestAbstractType getSamlRequest() {
        return samlRequest;
    }

    public String getRelayState() {
        return relayState;
    }

    public boolean isAuthnRequestSigned() {
        return isAuthnRequestSigned;
    }

    public X509Credential getIdPCredential() {
        return idPCredential;
    }

    public String getSigAlg() {
        return sigAlg;
    }

    public String getDigestAlg() {
        return digestAlg;
    }

    public static class SAML2SSOPostRequestResponseBuilder extends GatewayResponseBuilder {

        protected String saml2SSOUrl;
        protected RequestAbstractType samlRequest;
        protected String relayState;
        protected boolean isAuthnRequestSigned;
        protected X509Credential idPCredential;
        protected String sigAlg;
        protected String digestAlg;

        public SAML2SSOPostRequestResponseBuilder setSaml2SSOUrl(String saml2SSOUrl) {
            this.saml2SSOUrl = saml2SSOUrl;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setSamlRequest(RequestAbstractType samlRequest) {
            this.samlRequest = samlRequest;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setAuthnRequestSigned(boolean authnRequestSigned) {
            isAuthnRequestSigned = authnRequestSigned;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setIdPCredential(X509Credential idPCredential) {
            this.idPCredential = idPCredential;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setSigAlg(String sigAlg) {
            this.sigAlg = sigAlg;
            return this;
        }

        public SAML2SSOPostRequestResponseBuilder setDigestAlg(String digestAlg) {
            this.digestAlg = digestAlg;
            return this;
        }

        public SAML2SSOPostRequestResponse build() {
            return new SAML2SSOPostRequestResponse(this);
        }
    }
}
