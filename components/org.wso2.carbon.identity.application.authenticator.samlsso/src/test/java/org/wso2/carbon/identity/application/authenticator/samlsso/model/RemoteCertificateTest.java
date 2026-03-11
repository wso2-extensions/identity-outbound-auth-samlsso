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

package org.wso2.carbon.identity.application.authenticator.samlsso.model;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.security.auth.x500.X500Principal;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

/**
 * Unit tests for {@link RemoteCertificate}.
 */
public class RemoteCertificateTest {

    private static final Instant FIXED_INSTANT = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant OTHER_INSTANT = Instant.parse("2026-06-01T00:00:00Z");
    private static final Duration CACHE_DURATION_1H = Duration.ofHours(1);
    private static final Duration CACHE_DURATION_2H = Duration.ofHours(2);

    @Mock
    private X509Certificate mockCert1;

    @Mock
    private X509Certificate mockCert2;

    @BeforeClass
    public void setUp() {

        MockitoAnnotations.openMocks(this);

        when(mockCert1.getSerialNumber()).thenReturn(BigInteger.ONE);
        when(mockCert1.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TestCA1"));

        when(mockCert2.getSerialNumber()).thenReturn(BigInteger.TWO);
        when(mockCert2.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TestCA2"));
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            description = "Builder must reject a null certificate list.")
    public void testBuilderThrowsOnNullCertificates() {

        new RemoteCertificate.Builder(null).build();
    }

    @Test(description = "Builder stores the provided certificate list.")
    public void testBuilderStoresCertificates() {

        List<X509Certificate> certs = Collections.singletonList(mockCert1);
        RemoteCertificate rc = new RemoteCertificate.Builder(certs).build();

        assertEquals(rc.getCertificates(), certs);
    }

    @Test(description = "Builder sets validUntil correctly.")
    public void testBuilderSetsValidUntil() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .build();

        assertEquals(rc.getValidUntil(), FIXED_INSTANT);
    }

    @Test(description = "Builder sets cacheDuration correctly.")
    public void testBuilderSetsCacheDuration() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        assertEquals(rc.getCacheDuration(), CACHE_DURATION_1H);
    }

    @Test(description = "Builder sets lastRetrievedAt correctly.")
    public void testBuilderSetsLastRetrievedAt() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .lastRetrievedAt(FIXED_INSTANT)
                .build();

        assertEquals(rc.getLastRetrievedAt(), FIXED_INSTANT);
    }

    @Test(description = "createdAt is populated automatically during build.")
    public void testCreatedAtIsSetAutomatically() {

        Instant before = Instant.now();
        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();
        Instant after = Instant.now();

        assertNotNull(rc.getCreatedAt());
        assertFalse(rc.getCreatedAt().isBefore(before),
                "createdAt should not be before the instant the builder was constructed.");
        assertFalse(rc.getCreatedAt().isAfter(after),
                "createdAt should not be after the build completed.");
    }

    @Test(description = "validUntil defaults to null when not supplied.")
    public void testValidUntilDefaultsToNull() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();
        assertNull(rc.getValidUntil());
    }

    @Test(description = "cacheDuration defaults to null when not supplied.")
    public void testCacheDurationDefaultsToNull() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();
        assertNull(rc.getCacheDuration());
    }

    @Test(description = "lastRetrievedAt defaults to null when not supplied.")
    public void testLastRetrievedAtDefaultsToNull() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();
        assertNull(rc.getLastRetrievedAt());
    }

    @Test(expectedExceptions = UnsupportedOperationException.class,
            description = "The certificate list returned must be unmodifiable.")
    public void testCertificateListIsUnmodifiable() {

        RemoteCertificate rc = new RemoteCertificate.Builder(
                Arrays.asList(mockCert1, mockCert2)).build();
        rc.getCertificates().add(mockCert1);
    }

    @Test(description = "setLastRetrievedAt updates the stored value.")
    public void testSetLastRetrievedAt() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();
        assertNull(rc.getLastRetrievedAt());

        rc.setLastRetrievedAt(FIXED_INSTANT);
        assertEquals(rc.getLastRetrievedAt(), FIXED_INSTANT);
    }

    @Test(description = "setLastRetrievedAt accepts null to clear the value.")
    public void testSetLastRetrievedAtAcceptsNull() {

        RemoteCertificate rc = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .lastRetrievedAt(FIXED_INSTANT)
                .build();

        rc.setLastRetrievedAt(null);
        assertNull(rc.getLastRetrievedAt());
    }

    @Test(description = "equals returns true for the same instance.")
    public void testEqualsReturnsTrueForSameInstance() {

        RemoteCertificate rc = buildDefault();
        assertEquals(rc, rc);
    }

    @Test(description = "equals returns false when compared with null.")
    public void testEqualsReturnsFalseForNull() {

        RemoteCertificate rc = buildDefault();
        assertFalse(rc.equals(null));
    }

    @Test(description = "equals returns false when compared with an object of a different type.")
    public void testEqualsReturnsFalseForDifferentType() {

        RemoteCertificate rc = buildDefault();
        assertFalse(rc.equals("not a RemoteCertificate"));
    }

    @Test(description = "Two instances with identical certificates, validUntil, and cacheDuration are equal.")
    public void testEqualsReturnsTrueForIdenticalData() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        assertEquals(rc1, rc2);
    }

    @Test(description = "equals returns false when certificates differ.")
    public void testEqualsReturnsFalseForDifferentCertificates() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert2))
                .validUntil(FIXED_INSTANT).build();

        assertFalse(rc1.equals(rc2));
    }

    @Test(description = "equals returns false when validUntil differs.")
    public void testEqualsReturnsFalseForDifferentValidUntil() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(OTHER_INSTANT).build();

        assertFalse(rc1.equals(rc2));
    }

    @Test(description = "equals returns false when one validUntil is null and the other is not.")
    public void testEqualsReturnsFalseWhenOneValidUntilIsNull() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();

        assertFalse(rc1.equals(rc2));
    }

    @Test(description = "equals returns false when cacheDuration differs.")
    public void testEqualsReturnsFalseForDifferentCacheDuration() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_1H).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_2H).build();

        assertFalse(rc1.equals(rc2));
    }

    @Test(description = "equals returns false when one cacheDuration is null and the other is not.")
    public void testEqualsReturnsFalseWhenOneCacheDurationIsNull() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_1H).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1)).build();

        assertFalse(rc1.equals(rc2));
    }

    @Test(description = "equals is order-independent for the certificate list.")
    public void testEqualsIsOrderIndependentForCertificates() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2)).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Arrays.asList(mockCert2, mockCert1)).build();

        assertEquals(rc1, rc2);
    }

    @Test(description = "equals ignores lastRetrievedAt.")
    public void testEqualsIgnoresLastRetrievedAt() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .lastRetrievedAt(FIXED_INSTANT).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .lastRetrievedAt(OTHER_INSTANT).build();

        assertEquals(rc1, rc2);
    }

    @Test(description = "Two instances with empty certificate lists and no optional fields are equal.")
    public void testEqualsWithEmptyCertificateLists() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.emptyList()).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.emptyList()).build();

        assertEquals(rc1, rc2);
    }

    @Test(description = "Equal objects must produce the same hashCode (equals/hashCode contract).")
    public void testHashCodeEqualObjectsHaveSameHashCode() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        assertEquals(rc1.hashCode(), rc2.hashCode());
    }

    @Test(description = "hashCode differs when validUntil differs.")
    public void testHashCodeDiffersWhenValidUntilDiffers() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .build();

        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(OTHER_INSTANT)
                .build();

        assertNotEquals(rc1.hashCode(), rc2.hashCode());
    }

    @Test(description = "hashCode differs when cacheDuration differs.")
    public void testHashCodeDiffersWhenCacheDurationDiffers() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_1H)
                .build();

        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .cacheDuration(CACHE_DURATION_2H)
                .build();

        assertNotEquals(rc1.hashCode(), rc2.hashCode());
    }

    @Test(description = "hashCode differs when the certificate set differs.")
    public void testHashCodeDiffersWhenCertsDiffer() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .build();

        RemoteCertificate rc2 = new RemoteCertificate.Builder(Collections.singletonList(mockCert2))
                .validUntil(FIXED_INSTANT)
                .build();

        assertNotEquals(rc1.hashCode(), rc2.hashCode());
    }

    @Test(description = "hashCode is order-independent for the certificate list.")
    public void testHashCodeIsOrderIndependentForCertificates() {

        RemoteCertificate rc1 = new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2)).build();
        RemoteCertificate rc2 = new RemoteCertificate.Builder(Arrays.asList(mockCert2, mockCert1)).build();

        assertEquals(rc1.hashCode(), rc2.hashCode());
    }

    private RemoteCertificate buildDefault() {

        return new RemoteCertificate.Builder(Collections.singletonList(mockCert1))
                .validUntil(FIXED_INSTANT)
                .cacheDuration(CACHE_DURATION_1H)
                .build();
    }
}
