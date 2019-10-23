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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.processor;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * This class is responsible for processing the processed response from the authentication framework
 * after framework Logout .
 */

public class SAMLSSOLogoutProcessor extends IdentityProcessor {

    /**
     * check whether there is a context for the IdentityRequest.
     *
     * @param identityRequest
     * @return
     */

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            return (context.getRequest() instanceof SAMLLogoutRequest);
        }
        return false;
    }

    /**
     * process the response from authentication framework and build the SAMLLogoutResponse.
     *
     * @param identityRequest
     * @return
     * @throws FrameworkException
     */

    @Override
    public SAMLLogoutResponse.SAMLLogoutResponseBuilder process(IdentityRequest identityRequest)
        throws FrameworkException {

        String sessionDataKey = identityRequest.getParameter(InboundConstants.RequestProcessor.CONTEXT_KEY);
        IdentityMessageContext context = InboundUtil.getContextFromCache(sessionDataKey);
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) context;
        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = new SAMLLogoutResponse.SAMLLogoutResponseBuilder
            (samlMessageContext);
        builder.setResponse(samlMessageContext.getResponse());
        builder.setAcsUrl(samlMessageContext.getAcsUrl());
        return builder;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return IdentityUtil.getServerURL("identity", false, false);
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
