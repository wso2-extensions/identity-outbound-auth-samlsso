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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.request;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class takes in a servlet request from the /identity servlet and
 * provides a builder to an SAMLLogoutRequest instance as the output.
 * Contains the canHandle() method inherited from the parent class which
 * dictates whether or not a certain servlet request can be handled by this class.
 */
public class SAMLLogoutRequestFactory extends HttpIdentityRequestFactory {

    public SAMLLogoutRequestFactory() {
        super();
    }

    @Override
    public String getName() {
        return "SAMLLogoutRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        return (StringUtils.isNotBlank(request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)));
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response)
        throws FrameworkClientException {


        SAMLLogoutRequest.SAMLLogoutRequestBuilder builder = new SAMLLogoutRequest.
            SAMLLogoutRequestBuilder(request, response);
        create(builder, request, response);
        return builder;
    }

    public void create(SAMLLogoutRequest.SAMLLogoutRequestBuilder builder,
                       HttpServletRequest request,
                       HttpServletResponse response) throws FrameworkClientException {

        super.create(builder, request, response);
        builder.isPost(StringUtils.isBlank(request.getQueryString()));
    }

}
