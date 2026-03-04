/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.samlsso.internal;

import org.mockito.MockedStatic;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.lang.reflect.Method;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit test cases for SAMLSSOAuthenticatorServiceComponent.
 */
public class SAMLSSOAuthenticatorServiceComponentTest {

    @DataProvider(name = "intermediateLoaderPageConfigProvider")
    public Object[][] intermediateLoaderPageConfigProvider() {

        return new Object[][] {
                // { configValue, expectedResult }
                {"true", true},
                {"True", true},
                {"TRUE", true},
                {"false", false},
                {"False", false},
                {"FALSE", false},
                {null, false},
                {"", false},
                {"invalid", false}
        };
    }

    @Test(dataProvider = "intermediateLoaderPageConfigProvider",
            description = "Test useIntermediateLoaderPage with various config values")
    public void testUseIntermediateLoaderPage(String configValue, boolean expected) throws Exception {

        try (MockedStatic<IdentityUtil> mockedIdentityUtil = mockStatic(IdentityUtil.class)) {
            mockedIdentityUtil.when(() -> IdentityUtil.getProperty(
                    SSOConstants.ServerConfig.USE_INTERMEDIATE_LOADER_PAGE_CONFIG_NAME))
                    .thenReturn(configValue);

            SAMLSSOAuthenticatorServiceComponent component = new SAMLSSOAuthenticatorServiceComponent();
            Method method = SAMLSSOAuthenticatorServiceComponent.class.getDeclaredMethod("useIntermediateLoaderPage");
            method.setAccessible(true);
            boolean result = (boolean) method.invoke(component);

            if (expected) {
                assertTrue(result, "Expected useIntermediateLoaderPage() to return true for config value: " + configValue);
            } else {
                assertFalse(result,
                        "Expected useIntermediateLoaderPage() to return false for config value: " + configValue);
            }
        }
    }
}
