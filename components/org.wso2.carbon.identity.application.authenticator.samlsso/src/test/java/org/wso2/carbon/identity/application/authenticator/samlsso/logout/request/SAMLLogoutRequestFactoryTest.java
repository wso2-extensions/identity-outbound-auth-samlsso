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

import java.util.Enumeration;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SAML2_POST_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SAML_SLO_URL;

/**
 * Unit test cases for SAMLLogoutRequestFactory.
 */
public class SAMLLogoutRequestFactoryTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest mockedHttpServletRequest;

    @Mock
    private HttpServletResponse mockedHttpServletResponse;

    @Mock
    private Enumeration<String> mockedList;

    private SAMLLogoutRequestFactory samlLogoutRequestFactory = new SAMLLogoutRequestFactory();

    @Test
    public void testCanHandle() {

        when(mockedHttpServletRequest.getParameter(HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(HTTP_POST_PARAM_SAML2_AUTH_REQ);
        when(mockedHttpServletRequest.getRequestURI()).thenReturn(INBOUND_SAML_SLO_URL);
        assertTrue(samlLogoutRequestFactory.canHandle(mockedHttpServletRequest, mockedHttpServletResponse),
                "Failed to handle for valid input");
    }

    @Test
    public void testCanHandleFalse() {

        when(mockedHttpServletRequest.getParameter(HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(null);
        when(mockedHttpServletRequest.getRequestURI()).thenReturn(INBOUND_SAML_SLO_URL);
        assertFalse(samlLogoutRequestFactory.canHandle(mockedHttpServletRequest, mockedHttpServletResponse),
                "Able to handle for invalid input");
    }

    @Test
    public void testCanHandleFalseWithURI() {

        when(mockedHttpServletRequest.getParameter(HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(HTTP_POST_PARAM_SAML2_AUTH_REQ);
        when(mockedHttpServletRequest.getRequestURI()).thenReturn("/identity/saml/sso");
        assertFalse(samlLogoutRequestFactory.canHandle(mockedHttpServletRequest, mockedHttpServletResponse),
                "Able to handle for invalid input");
    }


    @Test(expectedExceptions = ExceptionInInitializerError.class)
    public void testCreate() throws Exception {

        when(mockedHttpServletRequest.getQueryString()).thenReturn(SAML2_POST_REQUEST);
        when(mockedHttpServletRequest.getHeaderNames()).thenReturn(mockedList);
        when(mockedHttpServletRequest.getAttributeNames()).thenReturn(mockedList);

        SAMLLogoutRequestFactory requestFactory = new SAMLLogoutRequestFactory();
        SAMLLogoutRequest.SAMLLogoutRequestBuilder requestBuilder = (SAMLLogoutRequest.SAMLLogoutRequestBuilder)
                requestFactory.create(mockedHttpServletRequest, mockedHttpServletResponse);
        assertTrue(requestBuilder.build().isPost(),"Failed to handle for valid input");
    }
}
