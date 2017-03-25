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

import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;

/**
 * The AuthnRequest sent over post binding to the federated IdP.
 */
public class SAML2SSOPostRequestResponse extends SAML2SSORequestResponse {

    private static final long serialVersionUID = 2520601931198808145L;

    protected boolean isAuthnRequestSigned;
    protected transient X509Credential idPCredential = null;
    protected String sigAlg;
    protected String digestAlg;

    protected SAML2SSOPostRequestResponse(SAML2SSOPostRequestResponseBuilder builder) {
        super(builder);
        isAuthnRequestSigned = builder.isAuthnRequestSigned;
        idPCredential = builder.idPCredential;
        sigAlg = builder.sigAlg;
        digestAlg = builder.digestAlg;
    }

    public boolean isAuthnRequestSigned() {
        return isAuthnRequestSigned;
    }

    public X509Credential getIdPCredential() {
        if (idPCredential == null) {
            idPCredential = SAML2AuthUtils.getServerCredentials();
        }
        return idPCredential;
    }

    public String getSigAlg() {
        return sigAlg;
    }

    public String getDigestAlg() {
        return digestAlg;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SAML2SSOPostRequestResponse{");
        sb.append("isAuthnRequestSigned=").append(isAuthnRequestSigned);
        sb.append(", sigAlg='").append(sigAlg).append('\'');
        sb.append(", digestAlg='").append(digestAlg).append('\'');
        sb.append('}');
        return sb.toString();
    }

    /**
     * The builder for building SAML2SSOPostRequestResponse.
     */
    public static class SAML2SSOPostRequestResponseBuilder extends SAML2SSORequestResponseBuilder {

        protected boolean isAuthnRequestSigned;
        protected X509Credential idPCredential;
        protected String sigAlg;
        protected String digestAlg;

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
