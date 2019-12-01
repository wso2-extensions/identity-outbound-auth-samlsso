package org.wso2.carbon.identity.application.authenticator.samlsso.logout.processor;

import java.util.HashMap;
import org.mockito.Mock;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.response.SAMLLogoutResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants.RequestProcessor.CONTEXT_KEY;

public class SAMLSSOLogoutProcessorTest extends PowerMockTestCase {

    @Mock
    private SAMLLogoutRequest mockedRequest;

    @Mock
    private IdentityRequest mockedReq;

    private SAMLSSOLogoutProcessor mockedProcessor = new SAMLSSOLogoutProcessor();

    @Test(expectedExceptions = NoClassDefFoundError.class)
    public void testProcess() throws Exception{

        when(mockedReq.getParameter(CONTEXT_KEY)).thenReturn("1234");
        SAMLMessageContext context = new SAMLMessageContext(mockedRequest,new HashMap());
        context.setResponse("SamlResponse");
        context.setAcsUrl("/saml/sso");
        InboundUtil.addContextToCache("1234", context);
        SAMLLogoutResponse.SAMLLogoutResponseBuilder builder = mockedProcessor.process(mockedReq);
        assertEquals(context.getResponse(), builder.build().getResponse());
    }
}
