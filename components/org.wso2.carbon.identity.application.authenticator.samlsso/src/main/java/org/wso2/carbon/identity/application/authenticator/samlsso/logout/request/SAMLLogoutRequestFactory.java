/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.request;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor.SAMLLogoutRequestProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import java.util.regex.Matcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.SAML_SLO_ENDPOINT_URL_PATTERN;

/**
 * This class checks whether requests from the Identity servlet are SAML Requests and
 * provides a builder to an instance of SAMLLogoutRequest.
 */
public class SAMLLogoutRequestFactory extends HttpIdentityRequestFactory {

    private static final Log log = LogFactory.getLog(SAMLLogoutRequestProcessor.class);

    public SAMLLogoutRequestFactory() {

        super();
    }

    @Override
    public String getName() {

        return "SAMLLogoutRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        boolean canHandle = false;
        if (request != null) {
            Matcher matcher = SAML_SLO_ENDPOINT_URL_PATTERN.matcher(request.getRequestURI());
            if (matcher.matches() && StringUtils.isNotBlank(request.getParameter
                    (SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))) {
                canHandle = true;
            }
        }
        return canHandle;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        SAMLLogoutRequest.SAMLLogoutRequestBuilder builder = new SAMLLogoutRequest.
                SAMLLogoutRequestBuilder(request, response);
        super.create(builder, request, response);
        builder.isPost(StringUtils.isBlank(HTTPTransportUtils.getRawQueryStringParameter(request.getQueryString(),
                HTTP_POST_PARAM_SAML2_AUTH_REQ)));
        if (log.isDebugEnabled()) {
            log.debug("Query string : " + request.getQueryString());
        }
        return builder;
    }
}
