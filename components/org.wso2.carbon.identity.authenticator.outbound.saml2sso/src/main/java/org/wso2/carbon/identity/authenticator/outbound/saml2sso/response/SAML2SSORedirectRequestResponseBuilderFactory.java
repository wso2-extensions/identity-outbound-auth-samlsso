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

import com.google.common.net.HttpHeaders;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorRuntimeException;
import org.wso2.carbon.identity.common.base.Constants;
import org.wso2.carbon.identity.common.base.exception.IdentityRuntimeException;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.ws.rs.core.Response;

/**
 * The factory responsible of building the MSS4J Response from SAML2SSORedirectRequestResponse.
 */
public class SAML2SSORedirectRequestResponseBuilderFactory extends GatewayResponseBuilderFactory {

    public boolean canHandle(GatewayResponse gatewayResponse) {
        return gatewayResponse instanceof SAML2SSORedirectRequestResponse;
    }

    @Override
    public void createBuilder(Response.ResponseBuilder builder, GatewayResponse gatewayResponse) {

        SAML2SSORedirectRequestResponse samlResponse;
        if (gatewayResponse instanceof SAML2SSORedirectRequestResponse) {
            samlResponse = (SAML2SSORedirectRequestResponse) gatewayResponse;
        } else {
            throw new SAML2SSOAuthenticatorRuntimeException("GatewayResponse object is not a " +
                                                            "SAML2SSORedirectRequestResponse.");
        }

        String saml2SSOUrl = samlResponse.getSaml2SSOUrl();
        StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + SAML2AuthUtils
                .encodeForRedirect(samlResponse.getSamlRequest()));
        try {
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode(samlResponse
                                                                                                       .getRelayState()
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
                SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                                                             samlResponse.getIdPCredential());
            } catch (IdentityRuntimeException e) {
                throw new SAML2SSOAuthenticatorRuntimeException("Error while signing AuthnRequest.", e);
            }

        }
        if (saml2SSOUrl.indexOf("?") > -1) {
            saml2SSOUrl = saml2SSOUrl.concat("&").concat(httpQueryString.toString());
        } else {
            saml2SSOUrl = saml2SSOUrl.concat("?").concat(httpQueryString.toString());
        }

        builder.status(302);
        builder.header(HttpHeaders.LOCATION, saml2SSOUrl);

    }

    @Override
    public Response.ResponseBuilder createBuilder(GatewayResponse gatewayResponse) {
        Response.ResponseBuilder builder = Response.noContent();
        createBuilder(builder, gatewayResponse);
        return builder;
    }

    public int getPriority() {
        return 75;
    }
}
