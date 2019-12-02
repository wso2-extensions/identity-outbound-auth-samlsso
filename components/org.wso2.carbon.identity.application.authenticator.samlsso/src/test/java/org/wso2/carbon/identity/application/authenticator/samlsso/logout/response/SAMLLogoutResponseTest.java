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

import static org.testng.Assert.assertEquals;

import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;

/**
 * Unit test cases for SAMLLogoutResponse
 */
public class SAMLLogoutResponseTest extends PowerMockTestCase {

    @Mock
    private SAMLMessageContext mockedContext;

    @Test
    public void testBuildResponse() {

        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = new SAMLLogoutResponse.SAMLLogoutResponseBuilder(mockedContext);
        builder.setRelayState("1234");
        builder.setAcsUrl("/travelocity.com");
        builder.setResponse("SAMLResponse");

        SAMLLogoutResponse response = builder.build();
        assertEquals("1234", response.getRelayState(),"Failed to handle for valid input");
        assertEquals("/travelocity.com", response.getAcsUrl(),"Failed to handle for valid input");
        assertEquals("SAMLResponse", response.getResponse(),"Failed to handle for valid input");
    }
}
