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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants.
        RequestProcessor.CONTEXT_KEY;
import static org.wso2.carbon.identity.base.IdentityConstants.IDENTITY_DEFAULT_ROLE;

/**
 * The class which processes the response from the authentication framework after framework Logout.
 */
public class SAMLSSOLogoutProcessor extends IdentityProcessor {

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        return context != null && (context.getRequest() instanceof SAMLLogoutRequest);
    }

    /**
     * Processes the response from the framework after framework logout.
     *
     * @param identityRequest {@link IdentityRequest} object.
     * @return SAMLLogoutResponse.SAMLLogoutResponseBuilder instance.
     */
    @Override
    public SAMLLogoutResponse.SAMLLogoutResponseBuilder process(IdentityRequest identityRequest) {

        String sessionDataKey = identityRequest.getParameter(CONTEXT_KEY);
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) InboundUtil.getContextFromCache(sessionDataKey);
        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = new SAMLLogoutResponse.SAMLLogoutResponseBuilder
                (samlMessageContext);
        builder.setResponse(samlMessageContext.getResponse());
        builder.setAcsUrl(samlMessageContext.getAcsUrl());
        builder.setRelayState(samlMessageContext.getRelayState());
        return builder;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return IdentityUtil.getServerURL(IDENTITY_DEFAULT_ROLE, false, false);
    }

    @Override
    public String getRelyingPartyId() {

        return null;
    }

    @Override
    public String getRelyingPartyId(IdentityMessageContext context) {

        return null;
    }

    @Override
    public int getPriority() {

        return 1;
    }
}
