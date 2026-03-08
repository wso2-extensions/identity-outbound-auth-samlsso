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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCache;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCacheEntry;
import org.wso2.carbon.identity.application.authenticator.samlsso.cache.SAMLCertCacheKey;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.RemoteCertificate;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Handles SAML signature verification using certificates resolved from a remote SAML metadata endpoint.
 */
public class RemoteCertificateProcessor {

    private static final Log LOG = LogFactory.getLog(RemoteCertificateProcessor.class);

    private static final RemoteCertificateProcessor INSTANCE = new RemoteCertificateProcessor();

    /**
     * Number of locks for synchronizing metadata fetches.
     */
    private static final int LOCK_COUNT = 64;

    /**
     * Array of locks used to synchronize metadata fetches for different metadata URLs.
     */
    private final ReentrantLock[] locks;

    private RemoteCertificateProcessor() {

        locks = new ReentrantLock[LOCK_COUNT];
        for (int i = 0; i < LOCK_COUNT; i++) {
            locks[i] = new ReentrantLock();
        }
    }

    /**
     * Returns the singleton instance of {@link RemoteCertificateProcessor}.
     *
     * @return the singleton instance.
     */
    public static RemoteCertificateProcessor getInstance() {

        return INSTANCE;
    }

    /**
     * Validates an XML {@link org.opensaml.xmlsec.signature.Signature} element against signing certificates
     * resolved from the IdP's SAML metadata endpoint.
     *
     * @param signature        The XML signature element to validate. Must be an instance of
     *                         {@link SignatureImpl}.
     * @param identityProvider The federated {@link IdentityProvider} whose SAML SSO authenticator configuration
     *                         supplies the metadata URL and the expected IDP entity ID.
     * @param tenantDomain     The tenant domain of the currently authenticated user.
     * @throws SAMLSSOException If no metadata URL is configured; if the metadata cannot be fetched or parsed;
     *                          or if the signature cannot be validated against any of the resolved certificates.
     */
    public void validateSignature(XMLObject signature, IdentityProvider identityProvider,
            String tenantDomain) throws SAMLSSOException {

        SignatureImpl signImpl = (SignatureImpl) signature;

        String metadataUrl = resolveMetadataUrl(identityProvider);
        if (StringUtils.isBlank(metadataUrl)) {
            throw new SAMLSSOException(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    String.format(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        String entityId = resolveEntityId(identityProvider);
        if (StringUtils.isBlank(entityId)) {
            throw new SAMLSSOException(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    String.format(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        List<X509Certificate> certificates = resolveCertificates(metadataUrl, entityId, tenantDomain);

        if (certificates == null || certificates.isEmpty()) {
            throw new SAMLSSOException(ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getCode(),
                    String.format(ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found " + certificates.size() + " remote signing certificate(s) for IdP: "
                    + identityProvider.getIdentityProviderName());
        }

        boolean isExceptionThrown = false;
        SignatureException validationException = null;
        int index = 0;
        ClassLoader opensamlCL = org.opensaml.xmlsec.signature.support.Signer.class.getClassLoader();

        for (X509Certificate cert : certificates) {
            X509CredentialImpl credential = new X509CredentialImpl(cert, entityId);
            ClassLoader oldCL = Thread.currentThread().getContextClassLoader();
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Validating SAML signature with remote certificate at index: " + index);
                }
                Thread.currentThread().setContextClassLoader(opensamlCL);
                SignatureValidator.validate(signImpl, credential);
                isExceptionThrown = false;
                break;
            } catch (SignatureException e) {
                isExceptionThrown = true;
                if (validationException == null) {
                    validationException = e;
                } else {
                    validationException.addSuppressed(e);
                }
            } finally {
                Thread.currentThread().setContextClassLoader(oldCL);
            }
            index++;
        }

        if (isExceptionThrown) {
            throw new SAMLSSOException(ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(),
                    ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage(),
                    validationException);
        }
    }

    /**
     * Attempts to refresh the signing certificates for the given {@link IdentityProvider} if the block duration
     * since the last retrieval attempt has elapsed.
     *
     * @param identityProvider The federated {@link IdentityProvider} whose SAML SSO authenticator configuration
     *                         supplies the metadata URL and the expected IDP entity ID.
     * @param tenantDomain     The tenant domain used to scope cache operations.
     * @throws SAMLSSOException If the metadata URL or entity ID is not configured; or if the metadata
     *                          cannot be fetched or parsed.
     */
    public boolean refreshCertificates(IdentityProvider identityProvider,
            String tenantDomain) throws SAMLSSOException {

        String metadataUrl = resolveMetadataUrl(identityProvider);
        if (StringUtils.isBlank(metadataUrl)) {
            throw new SAMLSSOException(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    String.format(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        String entityId = resolveEntityId(identityProvider);
        if (StringUtils.isBlank(entityId)) {
            throw new SAMLSSOException(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    String.format(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        SAMLCertCache cache = SAMLCertCache.getInstance();
        SAMLCertCacheKey cacheKey = new SAMLCertCacheKey(metadataUrl);
        Duration blockDuration = Duration.ofMillis(getCertRefreshRetryBlockDuration());

        SAMLCertCacheEntry cacheEntry = cache.getValueFromCache(cacheKey, tenantDomain);
        if (cacheEntry == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No existing cache entry for metadata URL: " + metadataUrl
                        + ". Skipping certificate refresh.");
            }
            return false;
        }

        RemoteCertificate cached = cacheEntry.getRemoteCertificate();
        if (isWithinBlockWindow(cached, blockDuration)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping certificate refresh for metadata URL: " + metadataUrl
                        + ". Block duration has not elapsed. Block duration: "
                        + blockDuration.toMillis() + "ms.");
            }
            return false;
        }

        ReentrantLock lock = getLockForKey(metadataUrl);
        lock.lock();
        try {
            // Double-check: another thread may have already refreshed while we were waiting for the lock.
            SAMLCertCacheEntry lockedEntry = cache.getValueFromCache(cacheKey, tenantDomain);
            if (lockedEntry == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No existing cache entry for metadata URL: " + metadataUrl
                            + ". Skipping certificate refresh.");
                }
                return false;
            }

            RemoteCertificate lockedCached = lockedEntry.getRemoteCertificate();
            if (isWithinBlockWindow(lockedCached, blockDuration)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipping certificate refresh for metadata URL: " + metadataUrl
                            + ". Block duration has not elapsed after acquiring lock.");
                }
                return false;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Attempting to refresh signing certificates from metadata URL: " + metadataUrl);
            }

            Instant now = Instant.now();
            RemoteCertificate fresh = SAMLMetadataCertificateResolver.getInstance()
                    .getSigningCertificatesFromMetadata(metadataUrl, entityId);

            if (!fresh.equals(lockedCached)) {
                // Certificates have changed — evict and replace the cache entry.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Refreshed certificates differ from cached certificates for metadata URL: "
                            + metadataUrl + ". Replacing cache entry.");
                }
                cache.clearCacheEntry(cacheKey, tenantDomain);
                cache.addToCache(cacheKey, new SAMLCertCacheEntry(fresh), tenantDomain);
                return true;
            } else {
                // Certificates are unchanged — potential DoS. Update lastRetrievedAt to reset the block window.
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Refreshed certificates match the existing cache entry for metadata URL: " + metadataUrl
                            + ". Treating as a potential DoS attempt. Updating lastRetrievedAt.");
                }
                lockedCached.setLastRetrievedAt(now);
                return false;
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the list of signing {@link X509Certificate}s for the given metadata URL.
     *
     * @param metadataUrl  The SAML metadata endpoint URL used as the cache key.
     * @param entityId     The IdP entity ID used when fetching from the metadata resolver to verify
     *                     that the retrieved EntityDescriptor matches the expected entity.
     * @param tenantDomain The tenant domain used to scope the {@link SAMLCertCache} operations so that
     *                     cached certificates are isolated per tenant.
     * @return The list of resolved signing certificates.
     * @throws SAMLSSOException If the metadata cannot be fetched, parsed, or does not contain
     *                          a matching EntityDescriptor.
     */
    private List<X509Certificate> resolveCertificates(String metadataUrl, String entityId,
            String tenantDomain) throws SAMLSSOException {

        SAMLCertCache cache = SAMLCertCache.getInstance();
        SAMLCertCacheKey cacheKey = new SAMLCertCacheKey(metadataUrl);

        SAMLCertCacheEntry cacheEntry = cache.getValueFromCache(cacheKey, tenantDomain);
        if (cacheEntry != null) {
            RemoteCertificate cached = cacheEntry.getRemoteCertificate();
            if (!isStale(cached)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using cached SAML signing certificates for metadata URL: " + metadataUrl);
                }
                return cached.getCertificates();
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cached entry is stale for metadata URL: " + metadataUrl
                        + ". Fetching fresh certificates from metadata endpoint.");
            }
        }

        ReentrantLock lock = getLockForKey(metadataUrl);
        lock.lock();
        try {
            // Double-check: another thread may have already fetched while we were waiting for the lock.
            SAMLCertCacheEntry lockedEntry = cache.getValueFromCache(cacheKey, tenantDomain);
            if (lockedEntry != null) {
                RemoteCertificate cached = lockedEntry.getRemoteCertificate();
                if (!isStale(cached)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Using cached SAML signing certificates for metadata URL "
                                + "(populated by another thread): " + metadataUrl);
                    }
                    return cached.getCertificates();
                }
            }

            // Cache miss or still stale — fetch from remote metadata endpoint.
            RemoteCertificate remoteCertificate = SAMLMetadataCertificateResolver.getInstance()
                    .getSigningCertificatesFromMetadata(metadataUrl, entityId);

            cache.clearCacheEntry(cacheKey, tenantDomain);
            cache.addToCache(cacheKey, new SAMLCertCacheEntry(remoteCertificate), tenantDomain);

            if (LOG.isDebugEnabled()) {
                LOG.debug("Fetched and cached " + remoteCertificate.getCertificates().size()
                        + " signing certificate(s) from metadata URL: " + metadataUrl);
            }

            return remoteCertificate.getCertificates();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns the lock corresponding to the given key using a consistent hashing strategy.
     * This ensures that the same lock is used for the same metadata URL, while allowing for concurrent
     * fetches for different URLs.
     * 
     * @param key The key to map to a lock (in this case, the metadata URL).
     * @return The lock corresponding to the given key.
     */
    private ReentrantLock getLockForKey(String key) {

        int index = (key.hashCode() & Integer.MAX_VALUE) % LOCK_COUNT;
        return locks[index];
    }

    /**
     * Determines whether the block duration since the last retrieval attempt has elapsed for a
     * cached {@link RemoteCertificate}.
     * 
     * @param remoteCertificate The cached remote certificate to evaluate.
     * @param blockDuration     The configured minimum interval between consecutive refresh attempts.
     * @return True if the block window is still active; false otherwise.
     */
    private boolean isWithinBlockWindow(RemoteCertificate remoteCertificate, Duration blockDuration) {

        return remoteCertificate.getLastRetrievedAt() != null
                && !Instant.now().isAfter(remoteCertificate.getLastRetrievedAt().plus(blockDuration));
    }

    /**
     * Determines whether a cached {@link RemoteCertificate} is stale.
     *
     * @param remoteCertificate The cached remote certificate to evaluate.
     * @return True if the entry should be discarded and re-fetched; false otherwise.
     */
    private boolean isStale(RemoteCertificate remoteCertificate) {

        Instant now = Instant.now();

        if (remoteCertificate.getValidUntil() != null && now.isAfter(remoteCertificate.getValidUntil())) {
            return true;
        }

        if (remoteCertificate.getCacheDuration() != null && remoteCertificate.getCreatedAt() != null) {
            Instant expiry = remoteCertificate.getCreatedAt().plus(remoteCertificate.getCacheDuration());
            if (now.isAfter(expiry)) {
                return true;
            }
        }

        if (remoteCertificate.getValidUntil() == null && remoteCertificate.getCacheDuration() == null) {
            Instant maxExpiry = remoteCertificate.getCreatedAt()
                    .plus(Duration.ofMillis(getCertCacheMaxLifetime()));
            if (now.isAfter(maxExpiry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolves the SAML metadata URL from the SAML SSO federated authenticator config of the given
     * {@link IdentityProvider}.
     *
     * @param identityProvider The {@link IdentityProvider} to read from.
     * @return The configured metadata URL, or null if not found.
     */
    private String resolveMetadataUrl(IdentityProvider identityProvider) {

        return resolveProperty(identityProvider, SSOConstants.SAML_METADATA_URI);
    }

    /**
     * Resolves the IdP entity ID from the SAML SSO federated authenticator config of the given
     * {@link IdentityProvider}.
     *
     * @param identityProvider The {@link IdentityProvider} to read from.
     * @return The configured IdP entity ID, or null if not found.
     */
    private String resolveEntityId(IdentityProvider identityProvider) {

        return resolveProperty(identityProvider,
                IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
    }

    /**
     * Finds a single named property from the SAML SSO federated authenticator config of the given
     * {@link IdentityProvider}.
     *
     * @param identityProvider The {@link IdentityProvider} to read from.
     * @param propertyName     The property name to look up.
     * @return The property value, or null if the authenticator config or the property is not found.
     */
    private String resolveProperty(IdentityProvider identityProvider, String propertyName) {

        FederatedAuthenticatorConfig[] configs = identityProvider.getFederatedAuthenticatorConfigs();
        if (configs == null) {
            return null;
        }

        for (FederatedAuthenticatorConfig config : configs) {
            if (!SSOConstants.AUTHENTICATOR_NAME.equals(config.getName())) {
                continue;
            }
            Property[] properties = config.getProperties();
            if (properties == null) {
                return null;
            }
            for (Property property : properties) {
                if (property != null && propertyName.equals(property.getName())) {
                    return property.getValue();
                }
            }
            return null;
        }

        return null;
    }

    /**
     * Returns the parameter map from the file-based authenticator configuration for the given authenticator name.
     *
     * @param authenticatorName The name of the authenticator whose parameter map should be retrieved.
     * @return The parameter map from the authenticator config, or an empty map if the config is not found
     *         or contains no parameters.
     */
    private Map<String, String> getAuthenticatorParamMap(String authenticatorName) {

        AuthenticatorConfig authenticatorConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(authenticatorName);
        if (authenticatorConfig != null && authenticatorConfig.getParameterMap() != null) {
            return authenticatorConfig.getParameterMap();
        }
        return Collections.emptyMap();
    }

    /**
     * Returns the configured CertRefreshRetryBlockDuration from the SAML SSO authenticator's
     * file-based configuration as milliseconds.
     *
     * @return The cert refresh retry block duration in milliseconds.
     */
    private long getCertRefreshRetryBlockDuration() {

        String value = getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME)
                .get(SSOConstants.CERT_REFRESH_RETRY_BLOCK_DURATION);
        if (StringUtils.isNotBlank(value)) {
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                LOG.error("Invalid value for '" + SSOConstants.CERT_REFRESH_RETRY_BLOCK_DURATION
                        + "': '" + value + "'. Using default "
                        + SSOConstants.DEFAULT_CERT_REFRESH_RETRY_BLOCK_DURATION_MS + "ms.");
            }
        }
        return SSOConstants.DEFAULT_CERT_REFRESH_RETRY_BLOCK_DURATION_MS;
    }

    /**
     * Returns the configured CertCacheMaxLifetime from the SAML SSO authenticator's
     * file-based configuration as milliseconds.
     *
     * @return The cert cache max lifetime in milliseconds.
     */
    private long getCertCacheMaxLifetime() {

        String value = getAuthenticatorParamMap(SSOConstants.AUTHENTICATOR_NAME)
                .get(SSOConstants.CERT_CACHE_MAX_LIFETIME);
        if (StringUtils.isNotBlank(value)) {
            try {
                return Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                LOG.error("Invalid value for '" + SSOConstants.CERT_CACHE_MAX_LIFETIME
                        + "': '" + value + "'. Using default "
                        + SSOConstants.DEFAULT_CERT_CACHE_MAX_LIFETIME_MS + "ms.");
            }
        }
        return SSOConstants.DEFAULT_CERT_CACHE_MAX_LIFETIME_MS;
    }

    /**
     * Validates a query string signature using the signing certificates resolved from the IdP's SAML metadata endpoint.
     * 
     * @param signature        The signature bytes to validate.
     * @param signedContent    The original content that was signed, used to verify the signature.
     * @param algorithmUri     The URI of the signature algorithm used, e.g. "http://www.w3.org/2000/09/xmldsig#rsa-sha1".
     * @param criteriaSet      The criteria set used for resolving credentials.
     * @param identityProvider The identity provider whose certificates are used for validation.
     * @param tenantDomain     The tenant domain of the identity provider.
     * @return true if the signature is valid, false otherwise.
     * @throws SAMLSSOException if an error occurs during signature validation.
     */
    public boolean validateQueryStringSignature(byte[] signature, byte[] signedContent,
            String algorithmUri, CriteriaSet criteriaSet,
            IdentityProvider identityProvider, String tenantDomain) throws SAMLSSOException {

        String metadataUrl = resolveMetadataUrl(identityProvider);
        if (StringUtils.isBlank(metadataUrl)) {
            throw new SAMLSSOException(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getCode(),
                    String.format(ErrorMessages.METADATA_URL_NOT_CONFIGURED_FOR_IDP.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        String entityId = resolveEntityId(identityProvider);
        if (StringUtils.isBlank(entityId)) {
            throw new SAMLSSOException(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getCode(),
                    String.format(ErrorMessages.IDP_ENTITY_ID_NOT_CONFIGURED.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        List<X509Certificate> certificates = resolveCertificates(metadataUrl, entityId, tenantDomain);
        if (certificates == null || certificates.isEmpty()) {
            throw new SAMLSSOException(ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getCode(),
                    String.format(ErrorMessages.NO_SIGNING_CERTIFICATES_FOUND_IN_METADATA.getMessage(),
                            identityProvider.getIdentityProviderName()));
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Found " + certificates.size() + " remote signing certificate(s) for IdP: "
                    + identityProvider.getIdentityProviderName()
                    + ". Attempting query string signature validation.");
        }

        try {
            for (X509Certificate certificate : certificates) {
                X509CredentialImpl credential = new X509CredentialImpl(certificate, entityId);
                List<Credential> credentials = new ArrayList<>();
                credentials.add(credential);
                CollectionCredentialResolver credentialResolver =
                        new CollectionCredentialResolver(credentials);
                KeyInfoCredentialResolver keyResolver = DefaultSecurityConfigurationBootstrap
                        .buildBasicInlineKeyInfoCredentialResolver();
                ExplicitKeySignatureTrustEngine engine =
                        new ExplicitKeySignatureTrustEngine(credentialResolver, keyResolver);
                if (engine.validate(signature, signedContent, algorithmUri, criteriaSet, null)) {
                    return true;
                }
            }
            return false;
        } catch (SecurityException e) {
            throw new SAMLSSOException(ErrorMessages.SIGNATURE_VALIDATION_FAILED.getCode(),
                    ErrorMessages.SIGNATURE_VALIDATION_FAILED.getMessage(), e);
        }
    }
}
