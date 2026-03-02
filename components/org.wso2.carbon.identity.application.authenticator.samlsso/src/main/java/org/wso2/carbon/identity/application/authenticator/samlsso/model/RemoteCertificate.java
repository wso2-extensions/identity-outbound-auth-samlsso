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

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents the X.509 certificates and associated metadata retrieved from a remote SAML metadata endpoint.
 */
public class RemoteCertificate {

    private final List<X509Certificate> certificates;
    private final Instant validUntil;
    private final Duration cacheDuration;
    private final Instant createdAt;
    private Instant lastRetrievedAt;

    private RemoteCertificate(Builder builder) {

        this.certificates = Collections.unmodifiableList(builder.certificates);
        this.createdAt = builder.createdAt;
        this.validUntil = builder.validUntil;
        this.cacheDuration = builder.cacheDuration;
        this.lastRetrievedAt = builder.lastRetrievedAt;
    }

    /**
     * Returns the list of X.509 certificates retrieved from the remote SAML metadata.
     * 
     * @return An unmodifiable list of X509Certificates.
     */
    public List<X509Certificate> getCertificates() {

        return certificates;
    }

    /**
     * Returns the validUntil instant from the SAML metadata, if present.
     *
     * @return The validUntil instant, or null if not specified in the metadata.
     */
    public Instant getValidUntil() {

        return validUntil;
    }

    /**
     * Returns the cache duration specified in the SAML metadata, if present.
     *
     * @return The cache duration, or null if not specified in the metadata.
     */
    public Duration getCacheDuration() {

        return cacheDuration;
    }

    /**
     * Returns the timestamp when this RemoteCertificate instance was created.
     *
     * @return The creation timestamp.
     */
    public Instant getCreatedAt() {

        return createdAt;
    }

    /**
     * Returns the timestamp of the most recent metadata retrieval attempt for this certificate.
     *
     * @return The last-retrieved timestamp, or null if never retrieved.
     */
    public Instant getLastRetrievedAt() {

        return lastRetrievedAt;
    }

    /**
     * Sets the timestamp of the most recent metadata retrieval attempt.
     *
     * @param lastRetrievedAt The timestamp of the last retrieval of the remote certificate.
     */
    public void setLastRetrievedAt(Instant lastRetrievedAt) {

        this.lastRetrievedAt = lastRetrievedAt;
    }

    /**
     * Checks equality based on the list of certificates (by serial number and issuer), validUntil, and cacheDuration.
     *
     * @param obj The object to compare with.
     * @return True if both equals, false otherwise.
     */
    @Override
    public boolean equals(Object obj) {

        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteCertificate)) {
            return false;
        }
        RemoteCertificate other = (RemoteCertificate) obj;
        return Objects.equals(validUntil, other.validUntil)
                && Objects.equals(cacheDuration, other.cacheDuration)
                && certificatesMatch(other.certificates);
    }

    /**
     * Compares the certificate list of this instance against the given list by matching each certificate's
     * serial number and issuer DN. Order is not significant.
     *
     * @param other The certificate list from the other RemoteCertificate.
     * @return True if both lists represent the same set of certificates by serial number and issuer DN.
     */
    private boolean certificatesMatch(List<X509Certificate> other) {

        return buildCertFingerprints(certificates).equals(buildCertFingerprints(other));
    }

    /**
     * Builds a set of fingerprint strings for a list of certificates, where each fingerprint is a
     * combination of the certificate's serial number and issuer DN.
     *
     * @param certs List of X509Certificates to fingerprint.
     * @return Set of fingerprint strings.
     */
    private Set<String> buildCertFingerprints(List<X509Certificate> certs) {

        return certs.stream()
                .map(cert -> cert.getSerialNumber() + "|" + cert.getIssuerX500Principal().getName())
                .collect(Collectors.toSet());
    }

    /**
     * Builder for {@link RemoteCertificate}.
     */
    public static class Builder {

        private final List<X509Certificate> certificates;
        private Instant createdAt;
        private Instant validUntil;
        private Duration cacheDuration;
        private Instant lastRetrievedAt;

        /**
         * Creates a builder with the mandatory list of X.509 certificates.
         *
         * @param certificates Non-null list of X509Certificates resolved from the remote SAML metadata.
         * @throws IllegalArgumentException If certificates is null.
         */
        public Builder(List<X509Certificate> certificates) {

            if (certificates == null) {
                throw new IllegalArgumentException("Certificates must not be null.");
            }
            this.certificates = certificates;
            this.createdAt = Instant.now();
        }

        /**
         * Sets the validUntil instant from the SAML metadata.
         *
         * @param validUntil validUntil property from the SAML metadata.
         * @return This builder.
         */
        public Builder validUntil(Instant validUntil) {

            this.validUntil = validUntil;
            return this;
        }

        /**
         * Sets the cacheDuration from the SAML metadata.
         *
         * @param cacheDuration Cache duration from the SAML metadata.
         * @return This builder.
         */
        public Builder cacheDuration(Duration cacheDuration) {

            this.cacheDuration = cacheDuration;
            return this;
        }

        /**
         * Sets the timestamp of the most recent metadata retrieval attempt.
         *
         * @param lastRetrievedAt Last-retrieved timestamp; may be null.
         * @return This builder.
         */
        public Builder lastRetrievedAt(Instant lastRetrievedAt) {

            this.lastRetrievedAt = lastRetrievedAt;
            return this;
        }

        /**
         * Builds and returns a new RemoteCertificate instance.
         *
         * @return a new {@link RemoteCertificate}.
         */
        public RemoteCertificate build() {

            return new RemoteCertificate(this);
        }
    }
}
