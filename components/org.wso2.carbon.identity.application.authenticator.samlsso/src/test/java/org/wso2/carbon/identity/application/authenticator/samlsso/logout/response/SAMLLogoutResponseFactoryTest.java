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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.response;

import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_URL;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SESSION_INDEX;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.HTTP_POST_PARAM_SAML2_RESP;

/**
 * Unit test cases for SAMLLogoutResponseFactory
 */
public class SAMLLogoutResponseFactoryTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutResponse mockedIdentityResponse;

    private SAMLLogoutResponseFactory samlLogoutResponseFactory = new SAMLLogoutResponseFactory();

    @Test
    public void testCanHandle() {

        assertTrue(samlLogoutResponseFactory.canHandle(mockedIdentityResponse),"Failed to handle for valid input");
    }

    @Test
    public void testCreate() {

        when(mockedIdentityResponse.getResponse()).thenReturn(HTTP_POST_PARAM_SAML2_RESP);
        when(mockedIdentityResponse.getAcsUrl()).thenReturn(IDP_URL);
        when(mockedIdentityResponse.getRelayState()).thenReturn(INBOUND_SESSION_INDEX);

        HttpIdentityResponse.HttpIdentityResponseBuilder responseBuilder = samlLogoutResponseFactory.
                create(mockedIdentityResponse);
        assertTrue(responseBuilder.build().getBody().contains(HTTP_POST_PARAM_SAML2_RESP), "Failed to handle for valid input");
        assertTrue(responseBuilder.build().getBody().contains(IDP_URL), "Failed to handle for valid input");
        assertTrue(responseBuilder.build().getBody().contains(INBOUND_SESSION_INDEX), "Failed to handle for valid input");
    }
}
