package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import org.mockito.Mock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.util.SAMLLogoutUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.SAML2_SLO_POST_REQUEST;

@PrepareForTest({FileBasedConfigurationBuilder.class, IdentityUtil.class, DocumentBuilderFactory.class,
        KeyStoreManager.class, DOMImplementationRegistry.class})
public class ProcessorTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutRequest mockedRequest;
    @Test(expectedExceptions = ClassCastException.class)
    public void testProcess() throws Exception{


        SAMLLogoutRequestProcessor processor = new SAMLLogoutRequestProcessor();
        SAMLLogoutUtil.doBootstrap();
        when(mockedRequest.isPost()).thenReturn(true);
        PowerMockito.when(mockedRequest.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ)).thenReturn(SAML2_SLO_POST_REQUEST);

        assertNotNull(processor.process(mockedRequest));
    }
}
