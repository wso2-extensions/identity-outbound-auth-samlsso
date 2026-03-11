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

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.RemoteCertificate;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;

/**
 * Unit tests for {@link SAMLCertCacheEntry}.
 */
public class SAMLCertCacheEntryTest {

    @Mock
    private RemoteCertificate mockRemoteCertificate;

    private AutoCloseable mocks;

    @BeforeClass
    public void setUp() {

        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterClass
    public void tearDown() throws Exception {

        mocks.close();
    }

    @Test(description = "Test that getRemoteCertificate returns the exact object passed to the constructor.")
    public void testGetRemoteCertificate() {

        SAMLCertCacheEntry entry = new SAMLCertCacheEntry(mockRemoteCertificate);
        assertSame(entry.getRemoteCertificate(), mockRemoteCertificate,
                "getRemoteCertificate() should return the same RemoteCertificate instance passed at construction.");
    }

    @Test(description = "Test that the entry can be constructed with a null certificate without throwing.")
    public void testGetRemoteCertificateWithNull() {

        SAMLCertCacheEntry entry = new SAMLCertCacheEntry(null);
        assertNull(entry.getRemoteCertificate(),
                "getRemoteCertificate() should return null when the entry was constructed with null.");
    }

    @Test(description = "Test that distinct RemoteCertificate instances stored in separate entries are preserved independently.")
    public void testDistinctEntriesHoldIndependentCertificates() {

        RemoteCertificate anotherCertificate = org.mockito.Mockito.mock(RemoteCertificate.class);
        SAMLCertCacheEntry entry1 = new SAMLCertCacheEntry(mockRemoteCertificate);
        SAMLCertCacheEntry entry2 = new SAMLCertCacheEntry(anotherCertificate);

        assertSame(entry1.getRemoteCertificate(), mockRemoteCertificate,
                "Entry 1 should hold the first RemoteCertificate.");
        assertSame(entry2.getRemoteCertificate(), anotherCertificate,
                "Entry 2 should hold the second RemoteCertificate.");
    }
}
