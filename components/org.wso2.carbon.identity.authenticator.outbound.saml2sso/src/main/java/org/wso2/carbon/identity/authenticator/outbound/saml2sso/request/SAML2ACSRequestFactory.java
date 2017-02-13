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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.request;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.util.SAML2SSOConstants;
import org.wso2.carbon.identity.gateway.api.FrameworkClientException;
import org.wso2.carbon.identity.gateway.api.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.gateway.api.HttpIdentityResponse;
import org.wso2.msf4j.Request;

public class SAML2ACSRequestFactory extends HttpIdentityRequestFactory<SAML2ACSRequest
        .SAML2ACSRequestBuilder> {

    @Override
    public boolean canHandle(Request request) {

        String saml2SSOResponse = (String)request.getProperty(SAML2SSOConstants.SAML_RESPONSE);
        if(StringUtils.isNotBlank(saml2SSOResponse)) {
            return true;
        }
        return false ;
    }

    public SAML2ACSRequest.SAML2ACSRequestBuilder create(Request request) throws FrameworkClientException {
        SAML2ACSRequest.SAML2ACSRequestBuilder builder = new SAML2ACSRequest.SAML2ACSRequestBuilder();
        this.create(builder, request);
        return builder;
    }

    public void create(SAML2ACSRequest.SAML2ACSRequestBuilder builder, Request request) throws FrameworkClientException {
        super.create(builder, request);
        builder.setSAML2SSOResponse((String)request.getProperty(SAML2SSOConstants.SAML_RESPONSE));
        builder.setRequestDataKey((String)request.getProperty(SAML2SSOConstants.RELAY_STATE));
    }

    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception) {
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        builder.setStatusCode(400);
        builder.setBody(exception.getMessage());
        return builder;
    }
}
