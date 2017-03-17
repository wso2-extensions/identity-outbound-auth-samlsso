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

import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.bean.Config;
import org.wso2.carbon.identity.common.base.Constants;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;

import javax.ws.rs.core.Response;

/**
 * The factory responsible of building the MSS4J Response from SAML2SSOPostRequestResponse.
 */
public class SAML2SSOPostRequestResponseBuilderFactory extends GatewayResponseBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAML2SSOPostRequestResponseBuilderFactory.class);

    public boolean canHandle(GatewayResponse gatewayResponse) {
        return gatewayResponse instanceof SAML2SSOPostRequestResponse;
    }

    @Override
    public Response.ResponseBuilder createBuilder(GatewayResponse gatewayResponse) {
        Response.ResponseBuilder builder = Response.noContent();
        createBuilder(builder, gatewayResponse);
        return builder;
    }

    @Override
    public void createBuilder(Response.ResponseBuilder builder, GatewayResponse gatewayResponse) {

        SAML2SSOPostRequestResponse saml2Response = (SAML2SSOPostRequestResponse) gatewayResponse;
        builder.status(200);
        signSAMLResponse(saml2Response);
        String authnRequest = SAML2AuthUtils.encodeForPost((SAML2AuthUtils.marshall(saml2Response.getSamlRequest())));
        String body = buildPostPage(saml2Response.getSaml2SSOUrl(), authnRequest, saml2Response.getRelayState());
        builder.entity(body);
    }

    protected void signSAMLResponse(SAML2SSOPostRequestResponse response) {

        if (response.isAuthnRequestSigned()) {
            String sigAlg = response.getSigAlg();
            if (StringUtils.isBlank(sigAlg)) {
                sigAlg = Constants.XML.SignatureAlgorithmURI.RSA_SHA1;
            }
            String digAlg = response.getDigestAlg();
            if (StringUtils.isBlank(digAlg)) {
                digAlg = Constants.XML.DigestAlgorithmURI.SHA1;
            }
            SAML2AuthUtils.setSignature(response.getSamlRequest(), sigAlg, digAlg, true, response.getIdPCredential());
        }
    }

    protected String buildPostPage(String saml2SSOUrl, String samlRequest, String relayState) {

        String postPage  = Config.getInstance().getAuthnRequestPage();

        postPage = postPage.replace("$url", Encode.forHtmlAttribute(saml2SSOUrl));
        StringBuilder hiddenInputBuilder = new StringBuilder("");
        hiddenInputBuilder.append("<input type='hidden' name='" + SAML2AuthConstants.SAML_REQUEST + "' value='")
                .append(samlRequest).append("'>");
        if (relayState != null) {
            hiddenInputBuilder.append("<input type='hidden' name='" + SAML2AuthConstants.RELAY_STATE + "' value='")
                    .append(relayState).append("'>");
        }
        postPage = postPage.replace("<!--$params-->", hiddenInputBuilder.toString());
        if (log.isDebugEnabled()) {
            log.debug("SAML2 SSO Authenticator HTTP-POST page: " + postPage);
        }
        return postPage;
    }

    public int getPriority() {
        return 75;
    }
}
