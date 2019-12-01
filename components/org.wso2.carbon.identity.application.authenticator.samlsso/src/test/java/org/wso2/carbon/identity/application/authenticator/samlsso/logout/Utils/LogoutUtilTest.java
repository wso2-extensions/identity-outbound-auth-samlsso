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

import static org.testng.Assert.*;

import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.StatusCodes.SUCCESS_CODE;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.*;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

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
        when(mockedIndex.getSessionIndex()).thenReturn("123456");
        assertEquals(SAMLLogoutUtil.getSessionIndex(mockedLogoutReq), "123456");
    }


    @Test
    public void testBuildResponse() throws Exception{

        SAMLMessageContext mockedContext = new SAMLMessageContext(mockedIdentityRequest, new HashMap());
        Map<String, String> mockedFedIdPConfigs = new HashMap<>();
        mockedFedIdPConfigs.put(IS_SLO_REQUEST_ACCEPTED, "true");
        mockedFedIdPConfigs.put(SSO_URL, "https:localhost/9444/samlsso");
        mockedFedIdPConfigs.put(SP_ENTITY_ID, "localhost");
        mockedFedIdPConfigs.put(IS_AUTHN_RESP_SIGNED, "false");
        mockedFedIdPConfigs.put(INCLUDE_CERT,"false");
        mockedContext.setFedIdPConfigs(mockedFedIdPConfigs);
        mockedContext.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);

        LogoutResponse logoutResp = SAMLLogoutUtil.buildResponse(mockedContext, "1234",SUCCESS_CODE,"building logout response");
        assertEquals(logoutResp.getInResponseTo(),"1234");
        assertEquals(logoutResp.getStatus().getStatusCode().getValue(),SUCCESS_CODE);
        assertEquals(logoutResp.getStatus().getStatusMessage().getMessage(), "building logout response");
    }

}