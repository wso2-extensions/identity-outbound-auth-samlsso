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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;

/**
 * Unit tests for {@link SAMLCertCacheKey}.
 */
public class SAMLCertCacheKeyTest {

    private static final String METADATA_URL = "https://example.com/saml/metadata";
    private static final String OTHER_URL = "https://other.com/saml/metadata";

    @Test(description = "Test that getMetadataUrl returns the URL provided at construction time.")
    public void testGetMetadataUrl() {

        SAMLCertCacheKey key = new SAMLCertCacheKey(METADATA_URL);
        assertEquals(key.getMetadataUrl(), METADATA_URL,
                "getMetadataUrl() should return the URL passed to the constructor.");
    }

    @Test(description = "Test that two keys constructed with the same URL are considered equal.")
    public void testEqualsSameUrl() {

        SAMLCertCacheKey key1 = new SAMLCertCacheKey(METADATA_URL);
        SAMLCertCacheKey key2 = new SAMLCertCacheKey(METADATA_URL);
        assertEquals(key1, key2, "Two keys with the same metadata URL should be equal.");
    }

    @Test(description = "Test that two keys constructed with different URLs are not equal.")
    public void testNotEqualsDifferentUrl() {

        SAMLCertCacheKey key1 = new SAMLCertCacheKey(METADATA_URL);
        SAMLCertCacheKey key2 = new SAMLCertCacheKey(OTHER_URL);
        assertNotEquals(key1, key2, "Two keys with different metadata URLs should not be equal.");
    }

    @Test(description = "Test that a key is equal to itself (reflexivity).")
    public void testEqualsSameInstance() {

        SAMLCertCacheKey key = new SAMLCertCacheKey(METADATA_URL);
        assertEquals(key, key, "A key should be equal to itself.");
    }

    @Test(description = "Test that a key is not equal to null.")
    public void testNotEqualsNull() {

        SAMLCertCacheKey key = new SAMLCertCacheKey(METADATA_URL);
        assertFalse(key.equals(null), "A key should not be equal to null.");
    }

    @Test(description = "Test that a key is not equal to an object of a different type.")
    public void testNotEqualsDifferentType() {

        SAMLCertCacheKey key = new SAMLCertCacheKey(METADATA_URL);
        assertFalse(key.equals(METADATA_URL), "A key should not be equal to a String object.");
    }

    @Test(description = "Test that hashCode is consistent across multiple invocations.")
    public void testHashCodeConsistency() {

        SAMLCertCacheKey key = new SAMLCertCacheKey(METADATA_URL);
        int firstCall = key.hashCode();
        int secondCall = key.hashCode();
        assertEquals(firstCall, secondCall, "hashCode() should return the same value on repeated calls.");
    }

    @Test(description = "Test that equal keys produce the same hash code.")
    public void testHashCodeEqualForEqualKeys() {

        SAMLCertCacheKey key1 = new SAMLCertCacheKey(METADATA_URL);
        SAMLCertCacheKey key2 = new SAMLCertCacheKey(METADATA_URL);
        assertEquals(key1.hashCode(), key2.hashCode(),
                "Equal keys must have identical hash codes.");
    }

    @Test(description = "Test that keys with different URLs produce different hash codes.")
    public void testHashCodeDifferentForDistinctUrls() {

        SAMLCertCacheKey key1 = new SAMLCertCacheKey(METADATA_URL);
        SAMLCertCacheKey key2 = new SAMLCertCacheKey(OTHER_URL);
        assertNotEquals(key1.hashCode(), key2.hashCode(),
                "Keys with different metadata URLs should have different hash codes.");
    }
}
