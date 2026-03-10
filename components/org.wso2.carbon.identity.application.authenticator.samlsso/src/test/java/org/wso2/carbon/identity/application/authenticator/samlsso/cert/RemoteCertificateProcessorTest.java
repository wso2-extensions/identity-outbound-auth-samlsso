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

package org.wso2.carbon.identity.application.authenticator.samlsso.cert;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCache;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCacheEntry;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCacheKey;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.RemoteCertificate;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Unit tests for {@link RemoteCertificateProcessor}.
 */
public class RemoteCertificateProcessorTest {

    private static final String METADATA_URL = "https://idp.example.com/saml/metadata";
    private static final String ENTITY_ID = "https://idp.example.com";
    private static final String TENANT_DOMAIN = "carbon.super";

    @Mock
    private SAMLCertCache mockCache;

    @Mock
    private SAMLMetadataCertificateResolver mockResolver;

    private AutoCloseable mocks;

    @BeforeMethod
    public void setUp() {

        System.setProperty("carbon.home", this.getClass().getResource("/").getPath());
        mocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        mocks.close();
    }

    @Test(description = "Test that getInstance() always returns the same singleton instance.")
    public void testGetInstanceReturnsSameInstance() {

        RemoteCertificateProcessor first = RemoteCertificateProcessor.getInstance();
        RemoteCertificateProcessor second = RemoteCertificateProcessor.getInstance();
        assertSame(first, second,
                "RemoteCertificateProcessor.getInstance() should return the identical singleton on every call.");
    }

    @Test(description = "When a fresh cache entry exists, resolveCertificates should return the cached "
            + "certificates without invoking the metadata resolver.")
    public void testResolveCertificates_CacheHit_ReturnsCachedCertificates() throws Exception {

        X509Certificate mockCert = mock(X509Certificate.class);
        List<X509Certificate> cachedCerts = Collections.singletonList(mockCert);
        RemoteCertificate remoteCertificate = new RemoteCertificate.Builder(cachedCerts)
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);

            List<X509Certificate> result = invokeResolveCertificates(METADATA_URL, ENTITY_ID, TENANT_DOMAIN);

            assertEquals(result, cachedCerts,
                    "Should return the cached certificates when a fresh cache entry exists.");
            verify(mockResolver, never()).getSigningCertificatesFromMetadata(anyString(), anyString());
        }
    }

    @Test(description = "When no cache entry exists, resolveCertificates should fetch certificates from the "
            + "metadata resolver, store them in the cache, and return them.")
    public void testResolveCertificates_CacheMiss_FetchesFromResolverAndCaches() throws Exception {

        X509Certificate mockCert = mock(X509Certificate.class);
        List<X509Certificate> freshCerts = Collections.singletonList(mockCert);
        RemoteCertificate freshRemoteCert = new RemoteCertificate.Builder(freshCerts)
                .validUntil(Instant.now().plusSeconds(3600))
                .build();

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(null);
            when(mockResolver.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID))
                    .thenReturn(freshRemoteCert);

            List<X509Certificate> result = invokeResolveCertificates(METADATA_URL, ENTITY_ID, TENANT_DOMAIN);

            assertEquals(result, freshCerts,
                    "Should return the certificates fetched from the metadata resolver on a cache miss.");
            verify(mockResolver).getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);
            verify(mockCache).clearCacheEntry(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN));
            verify(mockCache).addToCache(any(SAMLCertCacheKey.class), any(SAMLCertCacheEntry.class),
                    eq(TENANT_DOMAIN));
        }
    }

    @Test(description = "When the cached entry is stale (validUntil is in the past), resolveCertificates "
            + "should fetch fresh certificates from the metadata resolver and replace the stale cache entry.")
    public void testResolveCertificates_StaleCacheEntry_FetchesFreshCertificates() throws Exception {

        X509Certificate staleCert = mock(X509Certificate.class);
        X509Certificate freshCert = mock(X509Certificate.class);

        RemoteCertificate staleRemoteCert = new RemoteCertificate.Builder(Collections.singletonList(staleCert))
                .validUntil(Instant.now().minusSeconds(1))
                .build();
        SAMLCertCacheEntry staleCacheEntry = new SAMLCertCacheEntry(staleRemoteCert);

        RemoteCertificate freshRemoteCert = new RemoteCertificate.Builder(Collections.singletonList(freshCert))
                .validUntil(Instant.now().plusSeconds(3600))
                .build();

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            // Both the initial staleness check and the double-check inside the lock see the stale entry.
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(staleCacheEntry);
            when(mockResolver.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID))
                    .thenReturn(freshRemoteCert);

            List<X509Certificate> result = invokeResolveCertificates(METADATA_URL, ENTITY_ID, TENANT_DOMAIN);

            assertEquals(result, Collections.singletonList(freshCert),
                    "Should return fresh certificates after the stale cache entry is replaced.");
            verify(mockResolver).getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID);
            verify(mockCache).clearCacheEntry(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN));
            verify(mockCache).addToCache(any(SAMLCertCacheKey.class), any(SAMLCertCacheEntry.class),
                    eq(TENANT_DOMAIN));
        }
    }

    @Test(description = "When two threads concurrently encounter a stale cache entry for the same metadata "
            + "URL, only the thread that first acquires the lock should fetch from the remote endpoint. "
            + "The waiting thread should discover the fresh entry on its double-check inside the lock "
            + "and return it without calling the metadata resolver.")
    public void testResolveCertificates_ConcurrentStaleCacheEntry_OnlyOneThreadFetchesFromMetadata()
            throws Exception {

        X509Certificate staleCert = mock(X509Certificate.class);
        X509Certificate freshCert = mock(X509Certificate.class);

        RemoteCertificate staleRemoteCert = new RemoteCertificate.Builder(Collections.singletonList(staleCert))
                .validUntil(Instant.now().minusSeconds(1))
                .build();
        RemoteCertificate freshRemoteCert = new RemoteCertificate.Builder(Collections.singletonList(freshCert))
                .validUntil(Instant.now().plusSeconds(3600))
                .build();

        // Live cache state; initially stale.
        AtomicReference<SAMLCertCacheEntry> cacheState =
                new AtomicReference<>(new SAMLCertCacheEntry(staleRemoteCert));

        // Obtain the same ReentrantLock that resolveCertificates will use for METADATA_URL, so Thread 1
        // can hold it directly without going through resolveCertificates itself.
        Method getLockMethod = RemoteCertificateProcessor.class
                .getDeclaredMethod("getLockForKey", String.class);
        getLockMethod.setAccessible(true);
        ReentrantLock theLock = (ReentrantLock) getLockMethod
                .invoke(RemoteCertificateProcessor.getInstance(), METADATA_URL);

        // Thread 1 signals once it has acquired the lock.
        CountDownLatch thread1HasLock = new CountDownLatch(1);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);

            // Cache reads always reflect the current live state.
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenAnswer(inv -> cacheState.get());

            // Thread 1 simulates a competing thread that already holds the lock and is mid-fetch.
            // It holds the lock, waits long enough for Thread 2 (main thread) to block at lock.lock(),
            // then stores the fresh entry in the shared cache state before releasing the lock.
            Thread thread1 = new Thread(() -> {
                theLock.lock();
                try {
                    thread1HasLock.countDown();
                    Thread.sleep(200); // Hold the lock while Thread 2 blocks on lock.lock().
                    cacheState.set(new SAMLCertCacheEntry(freshRemoteCert));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    theLock.unlock();
                }
            });
            thread1.start();

            assertTrue(thread1HasLock.await(5, TimeUnit.SECONDS),
                    "Thread 1 should acquire the lock and signal within 5 seconds.");

            // Thread 2 is the main test thread. MockedStatic works here because it was created on this
            // thread. It sees the stale entry pre-lock, blocks on lock.lock() while Thread 1 holds it,
            // then discovers the fresh entry on the double-check inside the lock and returns without
            // calling the metadata resolver.
            List<X509Certificate> result = invokeResolveCertificates(METADATA_URL, ENTITY_ID, TENANT_DOMAIN);

            thread1.join(5000);

            assertEquals(result, Collections.singletonList(freshCert),
                    "Thread 2 should return the fresh certificates stored by Thread 1 "
                            + "without invoking the metadata resolver.");
            verifyNoInteractions(mockResolver);
        }
    }

    @Test(description = "When lastRetrievedAt is null, isWithinBlockWindow should return false "
            + "regardless of the block duration.")
    public void testIsWithinBlockWindow_NullLastRetrievedAt_ReturnsFalse() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList()).build();

        boolean result = invokeIsWithinBlockWindow(cert, Duration.ofMinutes(5));

        assertFalse(result, "Should return false when lastRetrievedAt is null.");
    }

    @Test(description = "When Instant.now() is before lastRetrievedAt + blockDuration, "
            + "isWithinBlockWindow should return true (block window is still active).")
    public void testIsWithinBlockWindow_NowBeforeWindowExpiry_ReturnsTrue() throws Exception {

        Instant fixedNow = Instant.now();
        Duration blockDuration = Duration.ofMinutes(5);
        Instant lastRetrievedAt = fixedNow.minusSeconds(30);

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .lastRetrievedAt(lastRetrievedAt)
                .build();

        boolean result = invokeIsWithinBlockWindow(cert, blockDuration);

        assertTrue(result, "Should return true when now is before lastRetrievedAt + blockDuration.");
    }

    @Test(description = "When Instant.now() is after lastRetrievedAt + blockDuration, "
            + "isWithinBlockWindow should return false (block window has expired).")
    public void testIsWithinBlockWindow_NowAfterWindowExpiry_ReturnsFalse() throws Exception {

        Instant fixedNow = Instant.now();
        Duration blockDuration = Duration.ofMinutes(5);
        Instant lastRetrievedAt = fixedNow.minusSeconds(660);

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .lastRetrievedAt(lastRetrievedAt)
                .build();

        boolean result = invokeIsWithinBlockWindow(cert, blockDuration);

        assertFalse(result, "Should return false when now is after lastRetrievedAt + blockDuration.");
    }

    /**
     * Invokes the private {@code resolveCertificates} method on the singleton instance via reflection.
     */
    @SuppressWarnings("unchecked")
    private List<X509Certificate> invokeResolveCertificates(String metadataUrl, String entityId,
            String tenantDomain) throws Exception {

        Method method = RemoteCertificateProcessor.class.getDeclaredMethod(
                "resolveCertificates", String.class, String.class, String.class);
        method.setAccessible(true);
        return (List<X509Certificate>) method.invoke(
                RemoteCertificateProcessor.getInstance(), metadataUrl, entityId, tenantDomain);
    }

    @Test(description = "When validUntil is set and is in the past, isStale should return true.")
    public void testIsStale_ValidUntilInPast_ReturnsTrue() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().minusSeconds(1))
                .build();

        boolean result = invokeIsStale(cert);

        assertTrue(result, "Should return true when validUntil is in the past.");
    }

    @Test(description = "When validUntil is set and is in the future, isStale should return false.")
    public void testIsStale_ValidUntilInFuture_ReturnsFalse() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .build();

        boolean result = invokeIsStale(cert);

        assertFalse(result, "Should return false when validUntil is in the future.");
    }

    @Test(description = "When cacheDuration is set and createdAt + cacheDuration is in the past, "
            + "isStale should return true.")
    public void testIsStale_CacheDurationExpired_ReturnsTrue() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .cacheDuration(Duration.ofSeconds(-1))
                .build();

        boolean result = invokeIsStale(cert);

        assertTrue(result, "Should return true when createdAt + cacheDuration is in the past.");
    }

    @Test(description = "When cacheDuration is set and createdAt + cacheDuration is in the future, "
            + "isStale should return false.")
    public void testIsStale_CacheDurationNotExpired_ReturnsFalse() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .cacheDuration(Duration.ofHours(1))
                .build();

        boolean result = invokeIsStale(cert);

        assertFalse(result, "Should return false when createdAt + cacheDuration is in the future.");
    }

    @Test(description = "When both validUntil and cacheDuration are null and the configured max lifetime "
            + "has been exceeded, isStale should return true.")
    public void testIsStale_BothNullMaxLifetimeExceeded_ReturnsTrue() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, "-1");

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList()).build();

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            boolean result = invokeIsStale(cert);

            assertTrue(result, "Should return true when the max lifetime has been exceeded.");
        }
    }

    @Test(description = "When both validUntil and cacheDuration are null and the configured max lifetime "
            + "has not been exceeded, isStale should return false.")
    public void testIsStale_BothNullMaxLifetimeNotExceeded_ReturnsFalse() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME,
                String.valueOf(SSOConstants.DEFAULT_REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME_MS));

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList()).build();

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            boolean result = invokeIsStale(cert);

            assertFalse(result, "Should return false when the max lifetime has not been exceeded.");
        }
    }

    @Test(description = "When validUntil is in the future but cacheDuration has expired, "
            + "isStale should still return true because the cacheDuration check fires independently.")
    public void testIsStale_ValidUntilInFutureButCacheDurationExpired_ReturnsTrue() throws Exception {

        RemoteCertificate cert = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .cacheDuration(Duration.ofSeconds(-1))
                .build();

        boolean result = invokeIsStale(cert);

        assertTrue(result, "Should return true when cacheDuration has expired even if validUntil is in the future.");
    }

    @Test(description = "When getFederatedAuthenticatorConfigs() returns null, "
            + "resolveProperty should return null.")
    public void testResolveProperty_NullConfigs_ReturnsNull() throws Exception {

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs()).thenReturn(null);

        String result = invokeResolveProperty(idp, "anyProperty");

        assertNull(result, "Should return null when federated authenticator configs array is null.");
    }

    @Test(description = "When no config has the SAML SSO authenticator name, "
            + "resolveProperty should return null.")
    public void testResolveProperty_NoMatchingAuthenticatorConfig_ReturnsNull() throws Exception {

        FederatedAuthenticatorConfig otherConfig = mock(FederatedAuthenticatorConfig.class);
        when(otherConfig.getName()).thenReturn("OtherAuthenticator");

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{otherConfig});

        String result = invokeResolveProperty(idp, "anyProperty");

        assertNull(result, "Should return null when no config matches the SAML SSO authenticator name.");
    }

    @Test(description = "When the matching authenticator config has a null properties array, "
            + "resolveProperty should return null.")
    public void testResolveProperty_NullPropertiesArray_ReturnsNull() throws Exception {

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(null);

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{samlConfig});

        String result = invokeResolveProperty(idp, "anyProperty");

        assertNull(result, "Should return null when properties array on the matching config is null.");
    }

    @Test(description = "When the matching config has the target property, "
            + "resolveProperty should return its value.")
    public void testResolveProperty_PropertyFound_ReturnsValue() throws Exception {

        Property targetProperty = mock(Property.class);
        when(targetProperty.getName()).thenReturn("metadataUrl");
        when(targetProperty.getValue()).thenReturn("https://idp.example.com/metadata");

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(new Property[]{targetProperty});

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{samlConfig});

        String result = invokeResolveProperty(idp, "metadataUrl");

        assertEquals(result, "https://idp.example.com/metadata",
                "Should return the value of the matching property.");
    }

    @Test(description = "When the matching config has properties but none matches the target name, "
            + "resolveProperty should return null.")
    public void testResolveProperty_PropertyNotFound_ReturnsNull() throws Exception {

        Property otherProperty = mock(Property.class);
        when(otherProperty.getName()).thenReturn("someOtherProperty");

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(new Property[]{otherProperty});

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{samlConfig});

        String result = invokeResolveProperty(idp, "metadataUrl");

        assertNull(result, "Should return null when the target property is not in the properties array.");
    }

    @Test(description = "When the properties array contains a null element before the target property, "
            + "resolveProperty should skip it and return the target property value.")
    public void testResolveProperty_NullElementInPropertiesArray_SkipsNullAndReturnsValue() throws Exception {

        Property targetProperty = mock(Property.class);
        when(targetProperty.getName()).thenReturn("metadataUrl");
        when(targetProperty.getValue()).thenReturn("https://idp.example.com/metadata");

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(new Property[]{null, targetProperty});

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{samlConfig});

        String result = invokeResolveProperty(idp, "metadataUrl");

        assertEquals(result, "https://idp.example.com/metadata",
                "Should skip null elements and return the value of the matching property.");
    }

    @Test(description = "When configs contain a non-matching authenticator followed by the SAML SSO authenticator "
            + "with the target property, resolveProperty should return the correct value.")
    public void testResolveProperty_MultipleConfigs_ReturnsValueFromSamlConfig() throws Exception {

        FederatedAuthenticatorConfig otherConfig = mock(FederatedAuthenticatorConfig.class);
        when(otherConfig.getName()).thenReturn("OtherAuthenticator");

        Property targetProperty = mock(Property.class);
        when(targetProperty.getName()).thenReturn("metadataUrl");
        when(targetProperty.getValue()).thenReturn("https://idp.example.com/metadata");

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(new Property[]{targetProperty});

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{otherConfig, samlConfig});

        String result = invokeResolveProperty(idp, "metadataUrl");

        assertEquals(result, "https://idp.example.com/metadata",
                "Should skip non-matching configs and return the value from the SAML SSO config.");
    }

    /**
     * Invokes the private {@code resolveProperty} method on the singleton instance via reflection.
     */
    private String invokeResolveProperty(IdentityProvider identityProvider, String propertyName)
            throws Exception {

        Method method = RemoteCertificateProcessor.class.getDeclaredMethod(
                "resolveProperty", IdentityProvider.class, String.class);
        method.setAccessible(true);
        return (String) method.invoke(RemoteCertificateProcessor.getInstance(), identityProvider, propertyName);
    }

    /**
     * Invokes the private {@code isWithinBlockWindow} method on the singleton instance via reflection.
     */
    private boolean invokeIsWithinBlockWindow(RemoteCertificate cert, Duration blockDuration) throws Exception {

        Method method = RemoteCertificateProcessor.class.getDeclaredMethod(
                "isWithinBlockWindow", RemoteCertificate.class, Duration.class);
        method.setAccessible(true);
        return (boolean) method.invoke(RemoteCertificateProcessor.getInstance(), cert, blockDuration);
    }

    /**
     * Invokes the private {@code isStale} method on the singleton instance via reflection.
     */
    private boolean invokeIsStale(RemoteCertificate cert) throws Exception {

        Method method = RemoteCertificateProcessor.class.getDeclaredMethod(
                "isStale", RemoteCertificate.class);
        method.setAccessible(true);
        return (boolean) method.invoke(RemoteCertificateProcessor.getInstance(), cert);
    }

    @Test(description = "When the param map contains a valid numeric value for "
            + "REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, getCertRefreshRetryBlockDuration "
            + "should return the parsed long value.")
    public void testGetCertRefreshRetryBlockDuration_ValidValue_ReturnsParsedValue() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "600000");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertRefreshRetryBlockDuration();

            assertEquals(result, 600000L,
                    "Should return the parsed long value from the param map.");
        }
    }

    @Test(description = "When the param map has no entry for "
            + "REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, getCertRefreshRetryBlockDuration "
            + "should return the default value.")
    public void testGetCertRefreshRetryBlockDuration_MissingValue_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(new HashMap<>());

            long result = invokeGetCertRefreshRetryBlockDuration();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION_MS,
                    "Should return the default value when the param map has no entry for the key.");
        }
    }

    @Test(description = "When the param map contains a blank value for "
            + "REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, getCertRefreshRetryBlockDuration "
            + "should return the default value.")
    public void testGetCertRefreshRetryBlockDuration_BlankValue_ReturnsDefault() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "   ");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertRefreshRetryBlockDuration();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION_MS,
                    "Should return the default value when the configured value is blank.");
        }
    }

    @Test(description = "When the param map contains a non-numeric value for "
            + "REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, getCertRefreshRetryBlockDuration "
            + "should fall back to the default value.")
    public void testGetCertRefreshRetryBlockDuration_InvalidValue_ReturnsDefault() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "not-a-number");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertRefreshRetryBlockDuration();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION_MS,
                    "Should return the default value when the configured value is not a valid number.");
        }
    }

    @Test(description = "When the param map contains a valid numeric value for "
            + "REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, getCertCacheMaxLifetime should return "
            + "the parsed long value.")
    public void testGetCertCacheMaxLifetime_ValidValue_ReturnsParsedValue() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, "172800000");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertCacheMaxLifetime();

            assertEquals(result, 172800000L,
                    "Should return the parsed long value from the param map.");
        }
    }

    @Test(description = "When the param map has no entry for REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, "
            + "getCertCacheMaxLifetime should return the default value.")
    public void testGetCertCacheMaxLifetime_MissingValue_ReturnsDefault() throws Exception {

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(new HashMap<>());

            long result = invokeGetCertCacheMaxLifetime();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME_MS,
                    "Should return the default value when the param map has no entry for the key.");
        }
    }

    @Test(description = "When the param map contains a blank value for "
            + "REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, getCertCacheMaxLifetime should return "
            + "the default value.")
    public void testGetCertCacheMaxLifetime_BlankValue_ReturnsDefault() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, "   ");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertCacheMaxLifetime();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME_MS,
                    "Should return the default value when the configured value is blank.");
        }
    }

    @Test(description = "When the param map contains a non-numeric value for "
            + "REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, getCertCacheMaxLifetime should fall back to "
            + "the default value.")
    public void testGetCertCacheMaxLifetime_InvalidValue_ReturnsDefault() throws Exception {

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME, "not-a-number");

        try (MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);

            long result = invokeGetCertCacheMaxLifetime();

            assertEquals(result, SSOConstants.DEFAULT_REMOTE_CERTIFICATE_CACHE_MAX_LIFETIME_MS,
                    "Should return the default value when the configured value is not a valid number.");
        }
    }

    /**
     * Invokes the private {@code getCertRefreshRetryBlockDuration} method on the singleton instance
     * via reflection.
     */
    private long invokeGetCertRefreshRetryBlockDuration() throws Exception {

        Method method = RemoteCertificateProcessor.class
                .getDeclaredMethod("getCertRefreshRetryBlockDuration");
        method.setAccessible(true);
        return (long) method.invoke(RemoteCertificateProcessor.getInstance());
    }

    /**
     * Invokes the private {@code getCertCacheMaxLifetime} method on the singleton instance via
     * reflection.
     */
    private long invokeGetCertCacheMaxLifetime() throws Exception {

        Method method = RemoteCertificateProcessor.class.getDeclaredMethod("getCertCacheMaxLifetime");
        method.setAccessible(true);
        return (long) method.invoke(RemoteCertificateProcessor.getInstance());
    }

    @Test(description = "When the metadata URL is not configured for the IdP, "
            + "refreshCertificates should throw SAMLSSOException with "
            + "METADATA_URL_NOT_CONFIGURED_FOR_IDP error code.")
    public void testRefreshCertificates_BlankMetadataUrl_ThrowsSAMLSSOException() {

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs()).thenReturn(null);
        when(idp.getIdentityProviderName()).thenReturn("TestIdP");

        try {
            RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    "Error code should indicate metadata URL is not configured.");
        }
    }

    @Test(description = "When the IdP entity ID is not configured, "
            + "refreshCertificates should throw SAMLSSOException with "
            + "IDP_ENTITY_ID_NOT_CONFIGURED error code.")
    public void testRefreshCertificates_BlankEntityId_ThrowsSAMLSSOException() {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, null);

        try {
            RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    "Error code should indicate entity ID is not configured.");
        }
    }

    @Test(description = "When there is no existing cache entry for the IdP, "
            + "refreshCertificates should return false without invoking the metadata resolver.")
    public void testRefreshCertificates_NoCacheEntry_ReturnsFalse() throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION,
                String.valueOf(SSOConstants.DEFAULT_REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION_MS));

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(null);

            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            assertFalse(result, "Should return false when there is no existing cache entry.");
            verify(mockResolver, never()).getSigningCertificatesFromMetadata(anyString(), anyString());
        }
    }

    @Test(description = "When the cached certificate is still within its block window, "
            + "refreshCertificates should return false without acquiring the lock or calling the resolver.")
    public void testRefreshCertificates_WithinBlockWindow_ReturnsFalse() throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        RemoteCertificate cached = new RemoteCertificate.Builder(Collections.emptyList())
                .lastRetrievedAt(Instant.now())
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(cached);

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "300000");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);

            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            assertFalse(result, "Should return false when the block window has not yet elapsed.");
            verify(mockResolver, never()).getSigningCertificatesFromMetadata(anyString(), anyString());
        }
    }

    @Test(description = "When the pre-lock check finds a cache entry but the double-check inside the lock "
            + "finds null (entry was concurrently evicted while waiting for the lock), "
            + "refreshCertificates should return false without invoking the metadata resolver.")
    public void testRefreshCertificates_DoubleCheckNullEntry_ReturnsFalse() throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        RemoteCertificate cached = new RemoteCertificate.Builder(Collections.emptyList()).build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(cached);

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "300000");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry)
                    .thenReturn(null);

            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            assertFalse(result,
                    "Should return false when the double-check inside the lock finds no cache entry.");
            verify(mockResolver, never()).getSigningCertificatesFromMetadata(anyString(), anyString());
        }
    }

    @Test(description = "When the refreshed certificates are identical to the cached ones, "
            + "refreshCertificates should update lastRetrievedAt to reset the block window and return false.")
    public void testRefreshCertificates_CertsUnchanged_UpdatesLastRetrievedAtAndReturnsFalse()
            throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        Instant validUntil = Instant.now().plusSeconds(3600);
        RemoteCertificate cached = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(validUntil)
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(cached);
        RemoteCertificate fresh = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(validUntil)
                .build();

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "300000");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            when(mockResolver.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID))
                    .thenReturn(fresh);

            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            assertFalse(result, "Should return false when the refreshed certificates are unchanged.");
            verify(mockCache, never()).clearCacheEntry(any(SAMLCertCacheKey.class), anyString());
            verify(mockCache, never()).addToCache(any(SAMLCertCacheKey.class), any(), anyString());
            assertTrue(cached.getLastRetrievedAt() != null,
                    "lastRetrievedAt should be updated on the cached object to reset the block window.");
        }
    }

    @Test(description = "When the refreshed certificates differ from the cached ones, "
            + "refreshCertificates should evict the stale cache entry, store the fresh one, and return true.")
    public void testRefreshCertificates_CertsChanged_ReplacesCacheAndReturnsTrue()
            throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        RemoteCertificate cached = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(cached);
        RemoteCertificate fresh = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(7200))
                .build();

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "300000");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            when(mockResolver.getSigningCertificatesFromMetadata(METADATA_URL, ENTITY_ID))
                    .thenReturn(fresh);

            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            assertTrue(result, "Should return true when the refreshed certificates have changed.");
            verify(mockCache).clearCacheEntry(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN));
            verify(mockCache).addToCache(any(SAMLCertCacheKey.class), any(SAMLCertCacheEntry.class),
                    eq(TENANT_DOMAIN));
        }
    }

    @Test(description = "When two threads concurrently attempt to refresh certificates, the first thread "
            + "that acquires the lock should complete the refresh and update lastRetrievedAt. "
            + "The second thread should discover the active block window on its double-check inside "
            + "the lock and return false without invoking the metadata resolver.")
    public void testRefreshCertificates_ConcurrentRefresh_SecondThreadEscapesViaDoubleCheck()
            throws Exception {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);

        RemoteCertificate staleRemoteCert = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        RemoteCertificate refreshedRemoteCert = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .lastRetrievedAt(Instant.now())
                .build();

        AtomicReference<SAMLCertCacheEntry> cacheState =
                new AtomicReference<>(new SAMLCertCacheEntry(staleRemoteCert));

        // Obtain the same ReentrantLock that refreshCertificates will use for METADATA_URL.
        Method getLockMethod = RemoteCertificateProcessor.class
                .getDeclaredMethod("getLockForKey", String.class);
        getLockMethod.setAccessible(true);
        ReentrantLock theLock = (ReentrantLock) getLockMethod
                .invoke(RemoteCertificateProcessor.getInstance(), METADATA_URL);

        CountDownLatch thread1HasLock = new CountDownLatch(1);

        Map<String, String> paramMap = new HashMap<>();
        paramMap.put(SSOConstants.REMOTE_CERTIFICATE_REFRESH_RETRY_BLOCK_DURATION, "300000");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SAMLMetadataCertificateResolver> resolverStatic =
                        mockStatic(SAMLMetadataCertificateResolver.class);
                MockedStatic<SSOUtils> ssoUtilsStatic = mockStatic(SSOUtils.class)) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            resolverStatic.when(SAMLMetadataCertificateResolver::getInstance).thenReturn(mockResolver);
            ssoUtilsStatic.when(() -> SSOUtils.getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME))
                    .thenReturn(paramMap);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenAnswer(inv -> cacheState.get());

            // Thread 1 simulates a competing thread that already holds the lock and is mid-refresh.
            // It holds the lock, waits for the main thread (Thread 2) to block at lock.lock(), then
            // replaces the cache state with a freshly-retrieved entry (lastRetrievedAt = now) before
            // releasing the lock. Thread 2's double-check will then see an active block window.
            Thread thread1 = new Thread(() -> {
                theLock.lock();
                try {
                    thread1HasLock.countDown();
                    Thread.sleep(200); // Hold the lock while Thread 2 blocks on lock.lock().
                    cacheState.set(new SAMLCertCacheEntry(refreshedRemoteCert));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    theLock.unlock();
                }
            });
            thread1.start();

            assertTrue(thread1HasLock.await(5, TimeUnit.SECONDS),
                    "Thread 1 should acquire the lock and signal within 5 seconds.");

            // Thread 2 (main thread): passes the pre-lock check (stale entry, block window inactive),
            // blocks on lock.lock() while Thread 1 holds it, then on the double-check inside the lock
            // finds that lastRetrievedAt was just updated — block window is now active — and returns false.
            boolean result = RemoteCertificateProcessor.getInstance().refreshCertificates(idp, TENANT_DOMAIN);

            thread1.join(5000);

            assertFalse(result,
                    "Thread 2 should return false after escaping via the double-check inside the lock.");
            verify(mockResolver, never()).getSigningCertificatesFromMetadata(anyString(), anyString());
        }
    }

    @Test(description = "When the metadata URL is not configured for the IdP, "
            + "validateSignature should throw SAMLSSOException with "
            + "METADATA_URL_NOT_CONFIGURED_FOR_IDP error code.")
    public void testValidateSignature_BlankMetadataUrl_ThrowsSAMLSSOException() {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs()).thenReturn(null);
        when(idp.getIdentityProviderName()).thenReturn("TestIdP");

        try {
            RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    "Error code should indicate metadata URL is not configured.");
        }
    }

    @Test(description = "When the IdP entity ID is not configured, "
            + "validateSignature should throw SAMLSSOException with "
            + "IDP_ENTITY_ID_NOT_CONFIGURED error code.")
    public void testValidateSignature_BlankEntityId_ThrowsSAMLSSOException() {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, null);

        try {
            RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    "Error code should indicate entity ID is not configured.");
        }
    }

    @Test(description = "When resolveCertificates returns an empty certificate list, "
            + "validateSignature should throw SAMLSSOException with "
            + "NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA error code.")
    public void testValidateSignature_EmptyCertificateList_ThrowsSAMLSSOException() {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        RemoteCertificate remoteCertificate = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);

            try {
                RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
                fail("Expected SAMLSSOException to be thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getCode(),
                        "Error code should indicate no signing certificates were found in metadata.");
            }
        }
    }

    @Test(description = "When a single certificate is resolved and SignatureValidator.validate succeeds, "
            + "validateSignature should complete without throwing any exception.")
    public void testValidateSignature_SingleCertValidationSucceeds_NoExceptionThrown()
            throws SAMLSSOException {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate = new RemoteCertificate.Builder(Collections.singletonList(mockCert))
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SignatureValidator> validatorStatic = mockStatic(SignatureValidator.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            // Default behavior for a void static method is to do nothing — validation succeeds.
            validatorStatic.when(() -> SignatureValidator.validate(any(), any()))
                    .thenAnswer(invocation -> null);

            RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
        }
    }

    @Test(description = "When a single certificate is resolved and SignatureValidator.validate throws "
            + "SignatureException, validateSignature should throw SAMLSSOException with "
            + "SIGNATURE_VALIDATION_FAILED error code and the SignatureException as the cause.")
    public void testValidateSignature_SingleCertValidationFails_ThrowsSAMLSSOExceptionWithCause() {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate = new RemoteCertificate.Builder(Collections.singletonList(mockCert))
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);
        SignatureException signatureException = new SignatureException("Signature validation failed");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SignatureValidator> validatorStatic = mockStatic(SignatureValidator.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            validatorStatic.when(() -> SignatureValidator.validate(any(), any()))
                    .thenThrow(signatureException);

            try {
                RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
                fail("Expected SAMLSSOException to be thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(),
                        "Error code should indicate signature validation failed.");
                assertSame(e.getCause(), signatureException,
                        "The cause should be the original SignatureException.");
            }
        }
    }

    @Test(description = "When two certificates are resolved and SignatureValidator.validate fails on the "
            + "first but succeeds on the second, validateSignature should complete without throwing "
            + "any exception.")
    public void testValidateSignature_MultipleCerts_FirstFailsSecondSucceeds_NoExceptionThrown()
            throws SAMLSSOException {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert1 = mock(X509Certificate.class);
        X509Certificate mockCert2 = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SignatureValidator> validatorStatic = mockStatic(SignatureValidator.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            AtomicInteger callCount = new AtomicInteger(0);
            validatorStatic.when(() -> SignatureValidator.validate(any(), any()))
                    .thenAnswer(invocation -> {
                        if (callCount.getAndIncrement() == 0) {
                            throw new SignatureException("First certificate validation failed");
                        }
                        return null;
                    });

            RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
        }
    }

    @Test(description = "When two certificates are resolved and SignatureValidator.validate fails for "
            + "both, validateSignature should throw SAMLSSOException with SIGNATURE_VALIDATION_FAILED "
            + "error code, with the second SignatureException suppressed under the first.")
    public void testValidateSignature_AllCertsFailValidation_ThrowsSAMLSSOExceptionWithSuppressed() {

        SignatureImpl mockSignature = mock(SignatureImpl.class);
        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert1 = mock(X509Certificate.class);
        X509Certificate mockCert2 = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);
        SignatureException firstException = new SignatureException("First certificate validation failed");
        SignatureException secondException = new SignatureException("Second certificate validation failed");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<SignatureValidator> validatorStatic = mockStatic(SignatureValidator.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            AtomicInteger callCount = new AtomicInteger(0);
            validatorStatic.when(() -> SignatureValidator.validate(any(), any()))
                    .thenAnswer(invocation -> {
                        if (callCount.getAndIncrement() == 0) {
                            throw firstException;
                        }
                        throw secondException;
                    });

            try {
                RemoteCertificateProcessor.getInstance().validateSignature(mockSignature, idp, TENANT_DOMAIN);
                fail("Expected SAMLSSOException to be thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(),
                        "Error code should indicate signature validation failed.");
                assertSame(e.getCause(), firstException,
                        "The cause should be the first SignatureException.");
                assertEquals(e.getCause().getSuppressed().length, 1,
                        "There should be exactly one suppressed exception.");
                assertSame(e.getCause().getSuppressed()[0], secondException,
                        "The suppressed exception should be the second SignatureException.");
            }
        }
    }

    @Test(description = "When the metadata URL is not configured for the IdP, "
            + "validateQueryStringSignature should throw SAMLSSOException with "
            + "METADATA_URL_NOT_CONFIGURED_FOR_IDP error code.")
    public void testValidateQueryStringSignature_BlankMetadataUrl_ThrowsSAMLSSOException() {

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs()).thenReturn(null);
        when(idp.getIdentityProviderName()).thenReturn("TestIdP");

        try {
            RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[0], new byte[0], "algorithmUri", mock(CriteriaSet.class), idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    "Error code should indicate metadata URL is not configured.");
        }
    }

    @Test(description = "When the IdP entity ID is not configured, "
            + "validateQueryStringSignature should throw SAMLSSOException with "
            + "IDP_ENTITY_ID_NOT_CONFIGURED error code.")
    public void testValidateQueryStringSignature_BlankEntityId_ThrowsSAMLSSOException() {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, null);

        try {
            RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[0], new byte[0], "algorithmUri", mock(CriteriaSet.class), idp, TENANT_DOMAIN);
            fail("Expected SAMLSSOException to be thrown.");
        } catch (SAMLSSOException e) {
            assertEquals(e.getErrorCode(),
                    ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    "Error code should indicate entity ID is not configured.");
        }
    }

    @Test(description = "When resolveCertificates returns an empty certificate list, "
            + "validateQueryStringSignature should throw SAMLSSOException with "
            + "NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA error code.")
    public void testValidateQueryStringSignature_EmptyCertificateList_ThrowsSAMLSSOException() {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        RemoteCertificate remoteCertificate = new RemoteCertificate.Builder(Collections.emptyList())
                .validUntil(Instant.now().plusSeconds(3600))
                .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class)) {
            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);

            try {
                RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                        new byte[0], new byte[0], "algorithmUri", mock(CriteriaSet.class), idp, TENANT_DOMAIN);
                fail("Expected SAMLSSOException to be thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getCode(),
                        "Error code should indicate no signing certificates were found in metadata.");
            }
        }
    }

    @Test(description = "When a single certificate is resolved and the trust engine validates "
            + "the signature successfully, validateQueryStringSignature should return true.")
    public void testValidateQueryStringSignature_SingleCert_TrustEngineReturnsTrue_ReturnsTrue()
            throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Collections.singletonList(mockCert))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<DefaultSecurityConfigurationBootstrap> bootstrapStatic =
                        mockStatic(DefaultSecurityConfigurationBootstrap.class);
                MockedConstruction<ExplicitKeySignatureTrustEngine> engineMock =
                        mockConstruction(ExplicitKeySignatureTrustEngine.class, (mock, context) ->
                                when(mock.validate(any(), any(), anyString(), any(), isNull()))
                                        .thenReturn(true))) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            bootstrapStatic.when(
                    DefaultSecurityConfigurationBootstrap::buildBasicInlineKeyInfoCredentialResolver)
                    .thenReturn(mock(KeyInfoCredentialResolver.class));

            boolean result = RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    mock(CriteriaSet.class), idp, TENANT_DOMAIN);

            assertTrue(result,
                    "Should return true when the trust engine validates the signature successfully.");
        }
    }

    @Test(description = "When a single certificate is resolved and the trust engine returns false, "
            + "validateQueryStringSignature should return false.")
    public void testValidateQueryStringSignature_SingleCert_TrustEngineReturnsFalse_ReturnsFalse()
            throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Collections.singletonList(mockCert))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<DefaultSecurityConfigurationBootstrap> bootstrapStatic =
                        mockStatic(DefaultSecurityConfigurationBootstrap.class);
                MockedConstruction<ExplicitKeySignatureTrustEngine> engineMock =
                        mockConstruction(ExplicitKeySignatureTrustEngine.class, (mock, context) ->
                                when(mock.validate(any(), any(), anyString(), any(), isNull()))
                                        .thenReturn(false))) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            bootstrapStatic.when(
                    DefaultSecurityConfigurationBootstrap::buildBasicInlineKeyInfoCredentialResolver)
                    .thenReturn(mock(KeyInfoCredentialResolver.class));

            boolean result = RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    mock(CriteriaSet.class), idp, TENANT_DOMAIN);

            assertFalse(result,
                    "Should return false when the trust engine returns false for the only certificate.");
        }
    }

    @Test(description = "When multiple certificates are resolved and the first fails but the second "
            + "succeeds, validateQueryStringSignature should return true without checking further.")
    public void testValidateQueryStringSignature_MultipleCerts_FirstFailsSecondSucceeds_ReturnsTrue()
            throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert1 = mock(X509Certificate.class);
        X509Certificate mockCert2 = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<DefaultSecurityConfigurationBootstrap> bootstrapStatic =
                        mockStatic(DefaultSecurityConfigurationBootstrap.class);
                MockedConstruction<ExplicitKeySignatureTrustEngine> engineMock =
                        mockConstruction(ExplicitKeySignatureTrustEngine.class, (mock, context) -> {
                            // context.getCount() is 1-based: first engine returns false, second returns true.
                            when(mock.validate(any(), any(), anyString(), any(), isNull()))
                                    .thenReturn(context.getCount() > 1);
                        })) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            bootstrapStatic.when(
                    DefaultSecurityConfigurationBootstrap::buildBasicInlineKeyInfoCredentialResolver)
                    .thenReturn(mock(KeyInfoCredentialResolver.class));

            boolean result = RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    mock(CriteriaSet.class), idp, TENANT_DOMAIN);

            assertTrue(result,
                    "Should return true when the second certificate's trust engine validates the signature.");
            assertEquals(engineMock.constructed().size(), 2,
                    "Both trust engines should have been constructed before finding a valid one.");
        }
    }

    @Test(description = "When multiple certificates are resolved and all fail validation, "
            + "validateQueryStringSignature should return false.")
    public void testValidateQueryStringSignature_AllCertsFail_ReturnsFalse() throws SAMLSSOException {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert1 = mock(X509Certificate.class);
        X509Certificate mockCert2 = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Arrays.asList(mockCert1, mockCert2))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<DefaultSecurityConfigurationBootstrap> bootstrapStatic =
                        mockStatic(DefaultSecurityConfigurationBootstrap.class);
                MockedConstruction<ExplicitKeySignatureTrustEngine> engineMock =
                        mockConstruction(ExplicitKeySignatureTrustEngine.class, (mock, context) ->
                                when(mock.validate(any(), any(), anyString(), any(), isNull()))
                                        .thenReturn(false))) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            bootstrapStatic.when(
                    DefaultSecurityConfigurationBootstrap::buildBasicInlineKeyInfoCredentialResolver)
                    .thenReturn(mock(KeyInfoCredentialResolver.class));

            boolean result = RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                    new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    mock(CriteriaSet.class), idp, TENANT_DOMAIN);

            assertFalse(result, "Should return false when all certificates fail validation.");
            assertEquals(engineMock.constructed().size(), 2,
                    "Both trust engines should have been constructed and tried.");
        }
    }

    @Test(description = "When the trust engine throws SecurityException during validation, "
            + "validateQueryStringSignature should throw SAMLSSOException with "
            + "SIGNATURE_VALIDATION_FAILED error code and the SecurityException as the cause.")
    public void testValidateQueryStringSignature_SecurityExceptionThrown_ThrowsSAMLSSOException() {

        IdentityProvider idp = buildIdentityProvider(METADATA_URL, ENTITY_ID);
        X509Certificate mockCert = mock(X509Certificate.class);
        RemoteCertificate remoteCertificate =
                new RemoteCertificate.Builder(Collections.singletonList(mockCert))
                        .validUntil(Instant.now().plusSeconds(3600))
                        .build();
        SAMLCertCacheEntry cacheEntry = new SAMLCertCacheEntry(remoteCertificate);
        SecurityException securityException = new SecurityException("Security failure during validation");

        try (MockedStatic<SAMLCertCache> cacheStatic = mockStatic(SAMLCertCache.class);
                MockedStatic<DefaultSecurityConfigurationBootstrap> bootstrapStatic =
                        mockStatic(DefaultSecurityConfigurationBootstrap.class);
                MockedConstruction<ExplicitKeySignatureTrustEngine> engineMock =
                        mockConstruction(ExplicitKeySignatureTrustEngine.class, (mock, context) ->
                                when(mock.validate(any(), any(), anyString(), any(), isNull()))
                                        .thenThrow(securityException))) {

            cacheStatic.when(SAMLCertCache::getInstance).thenReturn(mockCache);
            when(mockCache.getValueFromCache(any(SAMLCertCacheKey.class), eq(TENANT_DOMAIN)))
                    .thenReturn(cacheEntry);
            bootstrapStatic.when(
                    DefaultSecurityConfigurationBootstrap::buildBasicInlineKeyInfoCredentialResolver)
                    .thenReturn(mock(KeyInfoCredentialResolver.class));

            try {
                RemoteCertificateProcessor.getInstance().validateQueryStringSignature(
                        new byte[]{1, 2, 3}, new byte[]{4, 5, 6},
                        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                        mock(CriteriaSet.class), idp, TENANT_DOMAIN);
                fail("Expected SAMLSSOException to be thrown.");
            } catch (SAMLSSOException e) {
                assertEquals(e.getErrorCode(),
                        ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(),
                        "Error code should indicate signature validation failed.");
                assertSame(e.getCause(), securityException,
                        "The cause should be the original SecurityException.");
            }
        }
    }

    /**
     * Creates a mock {@link IdentityProvider} configured with the SAML SSO authenticator containing
     * the given metadata URL and entity ID properties.
     *
     * @param metadataUrl The metadata URL to configure, or null to omit.
     * @param entityId    The IdP entity ID to configure, or null to omit.
     * @return A configured mock {@link IdentityProvider}.
     */
    private IdentityProvider buildIdentityProvider(String metadataUrl, String entityId) {

        List<Property> properties = new ArrayList<>();
        if (metadataUrl != null) {
            Property metadataProp = mock(Property.class);
            when(metadataProp.getName()).thenReturn(SSOConstants.SAML_METADATA_URI);
            when(metadataProp.getValue()).thenReturn(metadataUrl);
            properties.add(metadataProp);
        }
        if (entityId != null) {
            Property entityIdProp = mock(Property.class);
            when(entityIdProp.getName())
                    .thenReturn(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
            when(entityIdProp.getValue()).thenReturn(entityId);
            properties.add(entityIdProp);
        }

        FederatedAuthenticatorConfig samlConfig = mock(FederatedAuthenticatorConfig.class);
        when(samlConfig.getName()).thenReturn(SSOConstants.AUTHENTICATOR_NAME);
        when(samlConfig.getProperties()).thenReturn(properties.toArray(new Property[0]));

        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getFederatedAuthenticatorConfigs())
                .thenReturn(new FederatedAuthenticatorConfig[]{samlConfig});
        when(idp.getIdentityProviderName()).thenReturn("TestIdP");
        return idp;
    }
}
