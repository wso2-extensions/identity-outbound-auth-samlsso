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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso;

import org.wso2.carbon.identity.framework.FrameworkClientException;
import org.wso2.carbon.identity.framework.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.framework.HttpIdentityResponse;
import org.wso2.carbon.identity.framework.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLFederatedRequestFactory <T extends SAMLFederatedRequest.SAMLFederatedRequestBuilder> extends HttpIdentityRequestFactory<T>{
    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        String samlResponse = request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.SAML_RESPONSE);
        if(samlResponse != null) {
            return true;
        }
        return false ;
    }

    @Override
    public void create(T builder, HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        super.create(builder, request, response);

        SAMLFederatedRequest.SAMLFederatedRequestBuilder samlFederatedRequestBuilder = (SAMLFederatedRequest.SAMLFederatedRequestBuilder)builder ;

        samlFederatedRequestBuilder.setSAMLResponse(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.SAML_RESPONSE));
        samlFederatedRequestBuilder.setRequestDataKey(request.getParameter(SAMLFederatedRequest.SAMLFederatedRequestConstants.RELAY_STATE));
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response)
            throws FrameworkClientException {

        SAMLFederatedRequest.SAMLFederatedRequestBuilder samlFederatedRequestBuilder = new SAMLFederatedRequest.SAMLFederatedRequestBuilder(request, response);
        create((T)samlFederatedRequestBuilder, request, response);

        return samlFederatedRequestBuilder ;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception,
                                                                            HttpServletRequest request,
                                                                            HttpServletResponse response) {
        return super.handleException(exception, request, response);
    }

    @Override
    public String getName() {
        return super.getName();
    }

    @Override
    public int getPriority() {
        return super.getPriority();
    }
}
