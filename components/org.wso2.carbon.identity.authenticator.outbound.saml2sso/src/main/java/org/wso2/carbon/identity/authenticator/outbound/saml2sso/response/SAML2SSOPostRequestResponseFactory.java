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
import org.wso2.carbon.identity.gateway.api.exception.FrameworkServerException;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponse;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.api.response.IdentityResponse;

public class SAML2SSOPostRequestResponseFactory extends HttpIdentityResponseFactory {

    private static Logger log = LoggerFactory.getLogger(SAML2SSOPostRequestResponseFactory.class);

    @Override
    public String getName() {
        return this.getName();
    }

    public boolean canHandle(IdentityResponse identityResponse) {
        return identityResponse instanceof SAML2SSOPostRequestResponse;
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
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder,
            IdentityResponse identityResponse) {

        SAML2SSOPostRequestResponse saml2Response = (SAML2SSOPostRequestResponse) identityResponse;
        builder.setStatusCode(200);
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
        builder.setBody(body);
        return builder;
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

        String postPage = null;
        // be able to read post page from config
        if (postPage != null) {

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

        } else {

            /*
            Need to convert this for MSS4J

            out.println("<html>");
            out.println("<body>");
            out.println("<p>You are now redirected to " + Encode.forHtml(saml2SSOUrl));
            out.println(" If the redirection fails, please click the post button.</p>");
            out.println("<form method='post' action='" + Encode.forHtmlAttribute(saml2SSOUrl) + "'>");
            out.println("<p>");

            out.println("<input type='hidden' name='SAMLRequest' value='" + samlRequest + "'>");
            out.println("<input type='hidden' name='RelayState' value='" + relayState + "'>");


            out.println("<button type='submit'>POST</button>");
            out.println("</p>");
            out.println("</form>");
            out.println("<script type='text/javascript'>");
            out.println("document.forms[0].submit();");
            out.println("</script>");
            out.println("</body>");
            out.println("</html>");
            */
        }
        return postPage;
    }
}
