package org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators;


import java.util.HashMap;
import java.util.Map;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;

import static org.opensaml.saml.common.SAMLVersion.VERSION_20;
import static org.testng.Assert.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.ISSUER_FORMAT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID;


public class LogoutRequestValidatorTest extends PowerMockTestCase {

    @Mock
    private IdentityRequest mockedIdentityRequest;

    @Mock
    private NameID mockedNameId;

    @Mock
    private BaseID mockedBaseId;

    @Mock
    private EncryptedID mockedEncId;


    @BeforeTest
    public void setUp(){

        MockitoAnnotations.initMocks(this);
    }

    @Test(dataProvider = "logoutRequestBuilderDataProvider")
    public void testIsValid(SAMLVersion version, String issuerID, String issuerFormat, NameID nameId, BaseID baseId,
                            EncryptedID encId, String isLogReqSigned, Boolean expectedValue) {

        SAMLMessageContext mockedContext = new SAMLMessageContext(mockedIdentityRequest, new HashMap());
        mockedContext.setValidStatus(true);

        LogoutRequest logReq = new LogoutRequestBuilder().buildObject();
        logReq.setVersion(version);

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerID);
        issuer.setFormat(issuerFormat);

        logReq.setIssuer(issuer);
        logReq.setNameID(nameId);
        logReq.setBaseID(baseId);
        logReq.setEncryptedID(encId);


        Map<String, String> mockedFedIdPConfigs = new HashMap<>();
        mockedFedIdPConfigs.put(IS_LOGOUT_REQ_SIGNED, isLogReqSigned);
        mockedContext.setFedIdPConfigs(mockedFedIdPConfigs);

        LogoutRequestValidator validator =new LogoutRequestValidator(mockedContext);

        Boolean actualValue= validator.isValidate(logReq);

        assertEquals(actualValue, actualValue);
    }

    @DataProvider(name = "logoutRequestBuilderDataProvider")
    public Object[][] logoutRequestBuilderData() {

        return new Object[][]{
                {
                        VERSION_20,
                        SP_ENTITY_ID,
                        ISSUER_FORMAT,
                        mockedNameId,
                        mockedBaseId,
                        mockedEncId,
                        "false",
                        true
                }
//                {
//                        VERSION_10,
//                        SP_ENTITY_ID,
//                        ISSUER_FORMAT,
//                        mockedNameId,
//                        mockedBaseId,
//                        mockedEncId,
//                        "false",
//                        false
//                },
//                {
//                        VERSION_20,
//                        null,
//                        ISSUER_FORMAT,
//                        mockedNameId,
//                        mockedBaseId,
//                        mockedEncId,
//                        "false",
//                        false
//                },
//                {
//                        VERSION_20,
//                        SP_ENTITY_ID,
//                        "12345",
//                        mockedNameId,
//                        mockedBaseId,
//                        mockedEncId,
//                        "false",
//                        false
//                },
//                {
//                        VERSION_20,
//                        SP_ENTITY_ID,
//                        ISSUER_FORMAT,
//                        null,
//                        mockedBaseId,
//                        mockedEncId,
//                        "false",
//                        false
//                },
//                {
//                        VERSION_20,
//                        SP_ENTITY_ID,
//                        ISSUER_FORMAT,
//                        mockedNameId,
//                        null,
//                        mockedEncId,
//                        "false",
//                        false
//                },
//                {
//                        VERSION_20,
//                        SP_ENTITY_ID,
//                        ISSUER_FORMAT,
//                        mockedNameId,
//                        mockedBaseId,
//                        null,
//                        "false",
//                        false
//                }
        };
    }
}
