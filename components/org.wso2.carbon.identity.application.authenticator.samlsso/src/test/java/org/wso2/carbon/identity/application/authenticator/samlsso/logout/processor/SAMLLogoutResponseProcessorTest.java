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

import java.util.HashMap;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.response.SAMLLogoutResponse;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants.RequestProcessor.CONTEXT_KEY;

/**
 * Unit test cases for SAMLLogoutRequestProcessor
 */
public class SAMLLogoutResponseProcessorTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutRequest mockedRequest;

    @Mock
    private IdentityRequest mockedReq;

    private SAMLLogoutResponseProcessor mockedProcessor = new SAMLLogoutResponseProcessor();

    @Test(expectedExceptions = NoClassDefFoundError.class)
    public void testProcess() {

        when(mockedReq.getParameter(CONTEXT_KEY)).thenReturn("1234");
        SAMLMessageContext context = new SAMLMessageContext(mockedRequest, new HashMap());
        context.setResponse("SamlResponse");
        context.setAcsUrl("/saml/sso");
        InboundUtil.addContextToCache("1234", context);
        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = mockedProcessor.process(mockedReq);
        assertEquals(context.getResponse(), builder.build().getResponse(), "Failed to handle for valid input");
    }
}
