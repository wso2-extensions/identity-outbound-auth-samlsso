/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.artifact;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.impl.ArtifactBuilder;
import org.opensaml.saml2.core.impl.ArtifactResolveBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;

public class SAMLSSOArtifactResolutionServiceTest {

    private static ArtifactResolve artifactResolve;

    @BeforeClass
    public void initTest() throws Exception {

        Configuration.getBuilderFactory().registerBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME,
                new ArtifactResolveBuilder());
        Configuration.getBuilderFactory().registerBuilder(Artifact.DEFAULT_ELEMENT_NAME, new ArtifactBuilder());
        Configuration.getBuilderFactory().registerBuilder(Issuer.DEFAULT_ELEMENT_NAME, new IssuerBuilder());
    }

    @Test(priority = 1)
    public void testGenerateArtifactResolveReq() throws ArtifactResolutionException {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID,
                TestConstants.SP_ENTITY_ID);
        SAMLSSOArtifactResolutionService artifactResolutionService = new SAMLSSOArtifactResolutionService(
                authenticatorProperties, TestConstants.SUPER_TENANT_DOMAIN);
        artifactResolve = artifactResolutionService.generateArtifactResolveReq(TestConstants.SAML_ART);
        assertEquals(artifactResolve.getIssuer().getValue(), TestConstants.SP_ENTITY_ID,
                "Issuer is not properly set in artifact resolve object.");
        assertEquals(artifactResolve.getArtifact().getArtifact(), TestConstants.SAML_ART,
                "Artifact is not properly set in artifact resolve object.");
    }
}
