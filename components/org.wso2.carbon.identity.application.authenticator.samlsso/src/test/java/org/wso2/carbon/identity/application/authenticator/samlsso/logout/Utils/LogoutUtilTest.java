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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.Utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;

import static org.testng.Assert.assertEquals;

import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_URL;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.INBOUND_SESSION_INDEX;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.StatusCodes.SUCCESS_CODE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_SLO_REQUEST_ACCEPTED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Unit test cases for SAMLLogoutUtil
 */
public class LogoutUtilTest extends PowerMockTestCase {

    @Mock
    private LogoutRequest mockedLogoutReq;

    @Mock
    private List<SessionIndex> mockedlist;

    @Mock
    private SessionIndex mockedIndex;

    @Mock
    private IdentityRequest mockedIdentityRequest;

    @Test
    public void testGetSessionIndex() throws Exception {

        when(mockedLogoutReq.getSessionIndexes()).thenReturn(mockedlist);
        when(mockedlist.get(0)).thenReturn(mockedIndex);
        when(mockedIndex.getSessionIndex()).thenReturn(INBOUND_SESSION_INDEX);
        assertEquals(SAMLLogoutUtil.getSessionIndex(mockedLogoutReq), INBOUND_SESSION_INDEX);
    }

    @Test
    public void testBuildResponse() throws Exception {

        SAMLMessageContext mockedContext = new SAMLMessageContext(mockedIdentityRequest, new HashMap());
        Map<String, String> mockedFedIdPConfigs = new HashMap<>();
        mockedFedIdPConfigs.put(IS_SLO_REQUEST_ACCEPTED, "true");
        mockedFedIdPConfigs.put(SSO_URL, IDP_URL);
        mockedFedIdPConfigs.put(SP_ENTITY_ID, "wso2is");
        mockedFedIdPConfigs.put(IS_AUTHN_RESP_SIGNED, "false");
        mockedFedIdPConfigs.put(INCLUDE_CERT, "false");
        mockedContext.setFedIdPConfigs(mockedFedIdPConfigs);
        mockedContext.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);

        LogoutResponse logoutResp = SAMLLogoutUtil.buildResponse(mockedContext, INBOUND_SESSION_INDEX,
                SUCCESS_CODE, "SAML logout response");
        assertEquals(logoutResp.getInResponseTo(), INBOUND_SESSION_INDEX, "Failed to handle for valid input");
        assertEquals(logoutResp.getStatus().getStatusCode().getValue(), SUCCESS_CODE, "Failed to handle for valid input");
        assertEquals(logoutResp.getStatus().getStatusMessage().getMessage(), "SAML logout response",
                "Failed to handle for valid input");
    }
}
