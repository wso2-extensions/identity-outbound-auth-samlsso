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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators;

import java.util.HashMap;
import java.util.Map;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.BaseID;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;

import static org.opensaml.saml.common.SAMLVersion.VERSION_20;
import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants.ISSUER_FORMAT;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
        SAML2SSO.IS_LOGOUT_REQ_SIGNED;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.Authenticator.
        SAML2SSO.SP_ENTITY_ID;

/**
 * Unit test cases for LogoutRequestValidator
 */
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
    public void setUp() {

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

        LogoutRequestValidator validator = new LogoutRequestValidator(mockedContext);
        Boolean actualValue = validator.isValidate(logReq);
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
        };
    }
}
