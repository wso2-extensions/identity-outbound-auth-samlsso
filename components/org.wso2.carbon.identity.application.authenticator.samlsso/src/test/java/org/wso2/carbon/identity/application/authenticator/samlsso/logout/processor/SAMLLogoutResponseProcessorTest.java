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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.core.ServiceURLBuilder;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants.RequestProcessor.CONTEXT_KEY;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.MockUtils.mockServiceURLBuilder;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SESSION_INDEX;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.HTTP_POST_PARAM_SAML2_RESP;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_URL;

/**
 * Unit test cases for SAMLLogoutRequestProcessor
 */
@PrepareForTest({InboundUtil.class, ServiceURLBuilder.class})
public class SAMLLogoutResponseProcessorTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutRequest mockedLogoutRequest;

    @Mock
    private IdentityRequest mockedIdentityRequest;

    private SAMLLogoutResponseProcessor mockedProcessor = new SAMLLogoutResponseProcessor();

    @Test
    public void testProcess() {

        when(mockedIdentityRequest.getParameter(CONTEXT_KEY)).thenReturn(INBOUND_SESSION_INDEX);
        SAMLMessageContext context = new SAMLMessageContext(mockedLogoutRequest, new HashMap());
        context.setResponse(HTTP_POST_PARAM_SAML2_RESP);
        context.setAcsUrl(IDP_URL);
        mockStatic(InboundUtil.class);
        when(InboundUtil.getContextFromCache(anyString())).thenReturn(context);
        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = mockedProcessor.process(mockedIdentityRequest);
        assertEquals(context.getResponse(), builder.build().getResponse(), "Failed to handle for valid input");
    }

    @Test
    public void testCanHandle() {

        when(mockedIdentityRequest.getParameter(CONTEXT_KEY)).thenReturn(INBOUND_SESSION_INDEX);
        SAMLMessageContext context = new SAMLMessageContext(mockedLogoutRequest, new HashMap());
        context.setResponse(HTTP_POST_PARAM_SAML2_RESP);
        context.setAcsUrl(IDP_URL);
        mockStatic(InboundUtil.class);
        when(InboundUtil.getContextFromCache(anyString())).thenReturn(context);
        assertTrue(mockedProcessor.canHandle(mockedIdentityRequest));
    }

    @Test
    public void testGetCallbackPath() {

        mockServiceURLBuilder();
        assertEquals(mockedProcessor.getCallbackPath(null), "https://localhost:9443/identity");
    }
}
