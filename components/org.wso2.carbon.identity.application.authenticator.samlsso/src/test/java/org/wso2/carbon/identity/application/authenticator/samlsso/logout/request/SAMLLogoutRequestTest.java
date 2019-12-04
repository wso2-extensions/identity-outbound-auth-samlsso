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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

/**
 * Unit test cases for  SAMLLogoutRequestTest
 */
public class SAMLLogoutRequestTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest mockedHttpRequest;

    @Mock
    private HttpServletResponse mockedHttpResponse;

    @Test
    public void testBuildRequest() throws Exception {

        SAMLLogoutRequest.SAMLLogoutRequestBuilder builder = new SAMLLogoutRequest.
                SAMLLogoutRequestBuilder(mockedHttpRequest, mockedHttpResponse);
        builder.isPost(true);
        SAMLLogoutRequest logoutRequest = builder.build();
        assertTrue(logoutRequest.isPost(), "Failed to handle for valid input");
    }
}
