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

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorException;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorRuntimeException;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.util.Utils;
import org.wso2.carbon.identity.common.base.Constants;
import org.wso2.carbon.identity.gateway.api.exception.FrameworkServerException;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponse;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.api.response.IdentityResponse;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class SAML2SSORedirectRequestResponseFactory extends HttpIdentityResponseFactory {

    @Override
    public String getName() {
        return this.getName();
    }

    public boolean canHandle(IdentityResponse identityResponse) {
        return identityResponse instanceof SAML2SSORedirectRequestResponse;
    }

    public boolean canHandle(FrameworkServerException exception) {
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        create(builder, identityResponse);
        return builder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        SAML2SSORedirectRequestResponse samlResponse = (SAML2SSORedirectRequestResponse) identityResponse;

        String saml2SSOUrl = samlResponse.getSaml2SSOUrl();
        StringBuilder httpQueryString = new StringBuilder("SAMLRequest=" + samlResponse.getSamlRequest());
        try {
            httpQueryString.append("&RelayState=" + URLEncoder.encode(samlResponse.getRelayState()
                    , StandardCharsets.UTF_8.name()).trim());
        } catch (UnsupportedEncodingException e) {
            throw new SAML2SSOAuthenticatorRuntimeException("Error occurred while url encoding RelayState.", e);
        }

        if (samlResponse.isAuthnRequestSigned()) {
            String signatureAlgo = samlResponse.getSigAlg();
            if (StringUtils.isBlank(signatureAlgo)) {
                signatureAlgo = Constants.XML.SignatureAlgorithmURI.RSA_SHA1;
            }
            try {
                Utils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo, samlResponse.getIdPCredential());
            } catch (SAML2SSOAuthenticatorException e) {
                // how to handle exceptions at factory level
                throw new SAML2SSOAuthenticatorRuntimeException("Error while signing AuthnRequest.", e);
            }

        }
        if (saml2SSOUrl.indexOf("?") > -1) {
            saml2SSOUrl = saml2SSOUrl.concat("&").concat(httpQueryString.toString());
        } else {
            saml2SSOUrl = saml2SSOUrl.concat("?").concat(httpQueryString.toString());
        }

        builder.setStatusCode(302);
        builder.setRedirectURL(saml2SSOUrl);
    }
}
