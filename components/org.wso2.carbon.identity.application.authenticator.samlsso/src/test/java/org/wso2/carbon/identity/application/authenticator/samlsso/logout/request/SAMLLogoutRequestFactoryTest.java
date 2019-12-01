package org.wso2.carbon.identity.application.authenticator.samlsso.logout.request;

import java.util.Enumeration;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SAML2_POST_REQUEST;

public class SAMLLogoutRequestFactoryTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest mockedHttpServletRequest;

    @Mock
    private HttpServletResponse mockedHttpServletResponse;

    @Mock
    private Enumeration<String> mockedList;


    private SAMLLogoutRequestFactory samlLogoutRequestFactory = new SAMLLogoutRequestFactory();

    @BeforeMethod
    public void setup() {

    }

    @Test
    public void testCanHandle() {

        when(mockedHttpServletRequest.getParameter("SAMLRequest")).thenReturn("SAMLRequest");
        when(mockedHttpServletRequest.getRequestURI()).thenReturn("/identity/saml/slo/");
        assertTrue(samlLogoutRequestFactory.canHandle(mockedHttpServletRequest, mockedHttpServletResponse),
                "Failed to handle for valid input");
    }

    @Test
    public void testCanHandleFalse() {

        when(mockedHttpServletRequest.getParameter("SAMLRequest")).thenReturn(null);
        when(mockedHttpServletRequest.getRequestURI()).thenReturn("/identity/saml/slo/");
        assertFalse(samlLogoutRequestFactory.canHandle(mockedHttpServletRequest, mockedHttpServletResponse),
                "Able to handle for invalid input");
    }

    @Test
    public void testCanHandleFalseWithURI() {

        when(mockedHttpServletRequest.getParameter("SAMLRequest")).thenReturn("SAMLRequest");
        when(mockedHttpServletRequest.getRequestURI()).thenReturn("/identity/saml/sso/");
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
        assertTrue(requestBuilder.build().isPost());
    }

}
