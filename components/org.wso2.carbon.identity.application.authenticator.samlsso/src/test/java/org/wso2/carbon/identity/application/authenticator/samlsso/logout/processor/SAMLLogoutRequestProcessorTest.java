package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.xpath.XPathFactory;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequestFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators.LogoutReqSignatureValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators.LogoutRequestValidator;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.RequestData;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.saml.saml2.core.StatusCode.SUCCESS;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.InboundRequestData.INBOUND_LOGOUT_REQUEST;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.*;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID;
import static org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@PowerMockIgnore({ "javax.xml.", "org.xml.", "org.w3c.*" })
@PrepareForTest({XPathFactory.class, XMLInputFactory.class, DocumentBuilderFactory.class, IdentityUtil.class,
        DOMImplementationRegistry.class, XMLObjectProviderRegistrySupport.class})
public class SAMLLogoutRequestProcessorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest mockedHttpServletRequest;

    @Mock
    private HttpServletResponse mockedHttpServletResponse;

    @Mock
    private SAMLMessageContext mockedSAMLMessageContext;

    @Mock
    private IdentityProvider mockedIdentityProvider;

    @Mock
    private LogoutRequestValidator mockedValidator;

    @Mock
    private IdentityRequest mockedIdentityRequest;

    @Mock
    private SAMLLogoutRequest mocke;

    private SAMLLogoutRequestProcessor samlLogoutRequestProcessor = new SAMLLogoutRequestProcessor();


    @Test
    public void testCanHandle(){
        assertTrue(samlLogoutRequestProcessor.canHandle(mockedIdentityRequest));
    }

    @DataProvider(name = "logoutRequestBuilderDataProvider")
    public Object[][] logoutRequestBuilderData() {

        return new Object[][]{

                {
                        INBOUND_LOGOUT_REQUEST.getRequestData()
                },
        };
    }

    @Test(expectedExceptions = SAMLSSOException.class)
    public void testProcessRedirectLogoutRequest() throws Exception{

        SAMLLogoutUtil.doBootstrap();
        when(mocke.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(SAML2_SLO_POST_REQUEST);
        when(mockedSAMLMessageContext.getSAMLLogoutRequest()).thenReturn(mocke);
        when(mocke.isPost()).thenReturn(Boolean.TRUE);
        //PowerMockito.doNothing().when(samlLogoutRequestProcessor,"populateContextWithSessionDetails",mockedSAMLMessageContext);

        //samlLogoutRequestProcessor.process(mocke);



        when(mockedSAMLMessageContext.getTenantDomain()).thenReturn(SUPER_TENANT_DOMAIN_NAME);
        when(mockedSAMLMessageContext.getIdPSessionID()).thenReturn("123456");

        Map<String, String> mockedFedIdPConfigs = new HashMap<>();
        mockedFedIdPConfigs.put(IS_SLO_REQUEST_ACCEPTED, "true");
        mockedFedIdPConfigs.put(SSO_URL, "https:localhost/9444/samlsso");
        mockedFedIdPConfigs.put(SP_ENTITY_ID, "localhost");
        mockedFedIdPConfigs.put(IS_AUTHN_RESP_SIGNED, "false");
        mockedFedIdPConfigs.put(INCLUDE_CERT,"false");
        when(mockedSAMLMessageContext.getFedIdPConfigs()).thenReturn(mockedFedIdPConfigs);
        when(mockedSAMLMessageContext.getFederatedIdP()).thenReturn(mockedIdentityProvider);
        when(mockedIdentityProvider.getIdentityProviderName()).thenReturn("IdP1");


        when(mockedSAMLMessageContext.getSAMLLogoutRequest()).thenReturn(mocke);
        when(mocke.isPost()).thenReturn(Boolean.TRUE);
        when(mocke.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(SAML2_LOGOUT_POST_REQUEST);

    }



}
