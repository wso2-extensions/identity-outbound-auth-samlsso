package org.wso2.carbon.identity.application.authenticator.samlsso.logout.response;

import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.dao.SessionInfoDAO;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class SAMLLogoutResponseFactoryTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutResponse mockedIdentityResponse;

    private SAMLLogoutResponseFactory samlLogoutResponseFactory = new SAMLLogoutResponseFactory();

    @Test
    public void testCanHandle(){


        assertTrue(samlLogoutResponseFactory.canHandle(mockedIdentityResponse));
    }

    @Test
    public void testCreate() {

        when(mockedIdentityResponse.getResponse()).thenReturn("SAMLResponse");
        when(mockedIdentityResponse.getAcsUrl()).thenReturn("saml/slo");
        when(mockedIdentityResponse.getRelayState()).thenReturn("1234");

        HttpIdentityResponse.HttpIdentityResponseBuilder responseBuilder = samlLogoutResponseFactory.
                create(mockedIdentityResponse);
        assertTrue(responseBuilder.build().getBody().contains("SAMLResponse"));
        assertTrue(responseBuilder.build().getBody().contains("saml/slo"));
        assertTrue(responseBuilder.build().getBody().contains("1234"));
    }

}
