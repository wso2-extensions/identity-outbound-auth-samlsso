/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.samlsso.cache;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for {@link SAMLCertCache}.
 */
public class SAMLCertCacheTest {

    @Test(description = "Test that getInstance() returns a non-null SAMLCertCache instance.")
    public void testGetInstanceReturnsNonNull() {

        SAMLCertCache instance = SAMLCertCache.getInstance();
        assertNotNull(instance, "SAMLCertCache.getInstance() must not return null.");
    }

    @Test(description = "Test that getInstance() always returns the same singleton instance.")
    public void testGetInstanceReturnsSameInstance() {

        SAMLCertCache first = SAMLCertCache.getInstance();
        SAMLCertCache second = SAMLCertCache.getInstance();
        assertSame(first, second,
                "SAMLCertCache.getInstance() should return the identical singleton on every call.");
    }
}
