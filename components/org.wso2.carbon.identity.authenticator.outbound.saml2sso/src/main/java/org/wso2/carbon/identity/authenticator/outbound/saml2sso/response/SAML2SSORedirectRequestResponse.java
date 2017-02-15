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
import org.wso2.carbon.identity.gateway.api.response.IdentityResponse;

public class SAML2SSORedirectRequestResponse extends IdentityResponse {

    protected String saml2SSOUrl;
    protected RequestAbstractType samlRequest;
    protected String relayState;
    protected boolean isAuthnRequestSigned;
    protected X509Credential idPCredential;
    protected String sigAlg;

    protected SAML2SSORedirectRequestResponse(SAML2SSORedirectRequestResponse.SAML2SSORedirectRequestResponseBuilder builder) {
        super(builder);
        saml2SSOUrl = builder.saml2SSOUrl;
        samlRequest = builder.samlRequest;
        relayState = builder.relayState;
        isAuthnRequestSigned = builder.isAuthnRequestSigned;
        idPCredential = builder.idPCredential;
        sigAlg = builder.sigAlg;
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

    public static class SAML2SSORedirectRequestResponseBuilder extends IdentityResponse.IdentityResponseBuilder {

        protected String saml2SSOUrl;
        protected RequestAbstractType samlRequest;
        protected String relayState;
        protected boolean isAuthnRequestSigned;
        protected X509Credential idPCredential;
        protected String sigAlg;

        public SAML2SSORedirectRequestResponseBuilder setSaml2SSOUrl(String saml2SSOUrl) {
            this.saml2SSOUrl = saml2SSOUrl;
            return this;
        }

        public SAML2SSORedirectRequestResponseBuilder setSamlRequest(RequestAbstractType samlRequest) {
            this.samlRequest = samlRequest;
            return this;
        }

        public SAML2SSORedirectRequestResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAML2SSORedirectRequestResponseBuilder setAuthnRequestSigned(boolean isAuthnRequestSigned) {
            this.isAuthnRequestSigned = isAuthnRequestSigned;
            return this;
        }

        public SAML2SSORedirectRequestResponseBuilder setIdPCredential(X509Credential idPCredential) {
            this.idPCredential = idPCredential;
            return this;
        }

        public SAML2SSORedirectRequestResponseBuilder setSigAlg(String sigAlg) {
            this.sigAlg = sigAlg;
            return this;
        }

        public SAML2SSORedirectRequestResponse build() {
            return new SAML2SSORedirectRequestResponse(this);
        }
    }
}
