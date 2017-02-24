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
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorException;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorRuntimeException;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.util.Utils;
import org.wso2.carbon.identity.common.base.Constants;
import org.wso2.carbon.identity.gateway.api.exception.GatewayServerException;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;

import javax.ws.rs.core.Response;

public class SAML2SSOPostRequestResponseBuilderFactory extends GatewayResponseBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAML2SSOPostRequestResponseBuilderFactory.class);

    @Override
    public String getName() {
        return this.getName();
    }

    public boolean canHandle(GatewayResponse gatewayResponse) {
        return gatewayResponse instanceof SAML2SSOPostRequestResponse;
    }

    public boolean canHandle(GatewayServerException exception) {
        return false;
    }


    @Override
    public Response.ResponseBuilder createBuilder(GatewayResponse gatewayResponse) {
        Response.ResponseBuilder builder = Response.noContent();
        createBuilder(builder,gatewayResponse);
        return builder ;
    }

    @Override
    public void createBuilder(Response.ResponseBuilder builder, GatewayResponse gatewayResponse) {

        SAML2SSOPostRequestResponse saml2Response = (SAML2SSOPostRequestResponse) gatewayResponse;
        builder.status(200);
        try {
            signSAMLResponse(saml2Response);
        } catch (SAML2SSOAuthenticatorException e) {
            // merge exception handling changes in inbound framework to gateway
            throw new SAML2SSOAuthenticatorRuntimeException("Error while signing AuthnRequest.", e);
        }
        String authnRequest = null;
        try {
            authnRequest = Utils.encodeForPost((Utils.marshall(saml2Response.getSamlRequest())));
        } catch (SAML2SSOAuthenticatorException e) {
            // merge exception handling changes in inbound framework to gateway
            throw new SAML2SSOAuthenticatorRuntimeException("Error while marshalling and encoding AuthnRequest.", e);
        }
        String body = buildPostPage(saml2Response.getSaml2SSOUrl(), authnRequest, saml2Response.getRelayState());
        builder.entity(body);
    }

    protected void signSAMLResponse(SAML2SSOPostRequestResponse response) throws SAML2SSOAuthenticatorException {


        if (response.isAuthnRequestSigned()) {
            String sigAlg = response.getSigAlg();
            if (StringUtils.isBlank(sigAlg)) {
                sigAlg = Constants.XML.SignatureAlgorithmURI.RSA_SHA1;
            }
            String digAlg = response.getDigestAlg();
            if (StringUtils.isBlank(digAlg)) {
                digAlg = Constants.XML.DigestAlgorithmURI.SHA1;
            }
            Utils.setSignature(response.getSamlRequest(), sigAlg, digAlg, true, response.getIdPCredential());
        }
    }

    protected String buildPostPage(String saml2SSOUrl, String samlRequest, String relayState) {

        // be able to read post page from config
        String postPage = postPage = "<html>\n" +
                                     "\t<body>\n" +
                                     "        \t<p>You are now redirected to $url \n" +
                                     "        \tIf the redirection fails, please click the post button.</p>\n" +
                                     "\n" +
                                     "        \t<form method='post' action='$url'>\n" +
                                     "       \t\t\t<p>\n" +
                                     "                    <!--$params-->\n" +
                                     "        \t\t\t<button type='submit'>POST</button>\n" +
                                     "       \t\t\t</p>\n" +
                                     "       \t\t</form>\n" +
                                     "       \t\t<script type='text/javascript'>\n" +
                                     "        \t\tdocument.forms[0].submit();\n" +
                                     "        \t</script>\n" +
                                     "        </body>\n" +
                                     "</html>";

        postPage = postPage.replace("$url", Encode.forHtmlAttribute(saml2SSOUrl));
        StringBuilder hiddenInputBuilder = new StringBuilder("");
        hiddenInputBuilder.append("<input type='hidden' name='SAMLRequest' value='")
                .append(samlRequest).append("'>");
        if (relayState != null) {
            hiddenInputBuilder.append("<input type='hidden' name='RelayState' value='")
                    .append(relayState).append("'>");
        }
        postPage = postPage.replace("<!--$params-->", hiddenInputBuilder.toString());
        if (log.isDebugEnabled()) {
            log.debug("SAML2 SSO Authenticator HTTP-POST page: " + postPage);
        }
        return postPage;
    }

    public int getPriority() {
        return 400;
    }
}
