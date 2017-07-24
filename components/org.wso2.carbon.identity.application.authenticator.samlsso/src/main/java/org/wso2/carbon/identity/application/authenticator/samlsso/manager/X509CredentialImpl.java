/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.manager;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.KeyProviderService;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import javax.crypto.SecretKey;

/**
 * X509Credential implementation for signing and verification.
 */
public class X509CredentialImpl implements X509Credential {

    private static final Log log = LogFactory.getLog(X509CredentialImpl.class);
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private X509Certificate entityCertificate = null;
    private KeyProviderService keyProviderService;

    /**
     * Instantiates X509Credential.
     * If the IDP cert passed is not null the instantiated credential object will hold the passed
     * cert and the public key of the cert.
     * Otherwise the object will hold the private key, public key and the cert for the respective
     * tenant domain.
     *
     * @param tenantDomain tenant domain
     * @param idpCert      certificate of the IDP
     * @param keyProviderService the key provider service
     * @throws SAMLSSOException In case cannot retrieve public, private keys from keystore
     */
    public X509CredentialImpl(String tenantDomain, String idpCert, KeyProviderService keyProviderService)
            throws SAMLSSOException {
        this.keyProviderService = keyProviderService;
        X509Certificate cert = null;

        /**
         * If IDP cert is passed as a parameter set the cert to the IDP cert.
         * IDP cert should be passed when used with response validation.
         */
        if (StringUtils.isNotEmpty(idpCert)) {
            try {
                cert = (X509Certificate) IdentityApplicationManagementUtil.decodeCertificate(idpCert);
            } catch (CertificateException e) {
                throw new SAMLSSOException("Error retrieving the certificate for alias " + idpCert, e);
            }
            if (cert == null) {
                throw new SAMLSSOException(
                        "Cannot find the certificate from IdP certificate: " + idpCert + " , for tenant: "
                                + tenantDomain);
            }
        } else {
            PrivateKey key = null;
            try {
                if (keyProviderService != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Using Key provider service to lookup the private key and certificates for " +
                                "tenant: " + tenantDomain);
                    }
                    key = keyProviderService.getPrivateKey(tenantDomain);
                    Certificate certificateFromService = keyProviderService.getCertificate(tenantDomain);
                    if (certificateFromService instanceof X509Certificate) {
                        cert = (X509Certificate) certificateFromService;
                    }
                }

                if (key == null) {
                    throw new SAMLSSOException(
                            "Error retrieving private key from keyProviderService for tenant " + tenantDomain);
                }
                if (cert == null) {
                    throw new SAMLSSOException(
                            "Error retrieving the X.509 Certificate from keyProviderService for tenant "
                                    + tenantDomain);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Key provider service was able to find the private key:" + key + " and certificate:"
                            + cert + " for tenant: " + tenantDomain);
                }
            } catch (IdentityException e) {
                throw new SAMLSSOException(
                        "Error retrieving private key or the certificate from keyProviderService for tenant: "
                                + tenantDomain, e);
            }

            this.privateKey = key;
        }

        entityCertificate = cert;
        publicKey = cert.getPublicKey();
    }

    /**
     * Instantiates X509Credential.
     * If the IDP cert passed is not null the instantiated credential object will hold the passed
     * cert and the public key of the cert.
     * Otherwise the object will hold the private key, public key and the cert for the respective
     * tenant domain.
     *
     * @param tenantDomain tenant domain
     * @param idpCert      certificate of the IDP
     * @throws SAMLSSOException
     * @deprecated please use X509CredentialImpl(String tenantDomain, String idpCert, KeyProviderService keyProviderService)
     */
    @Deprecated
    public X509CredentialImpl(String tenantDomain, String idpCert) throws SAMLSSOException {

        X509Certificate cert = null;

        /**
         * If IDP cert is passed as a parameter set the cert to the IDP cert.
         * IDP cert should be passed when used with response validation.
         */
        if (idpCert != null && !idpCert.isEmpty()) {
            try {
                cert = (X509Certificate) IdentityApplicationManagementUtil
                        .decodeCertificate(idpCert);
            } catch (CertificateException e) {
                throw new SAMLSSOException(
                        "Error retrieving the certificate for alias " + idpCert, e);
            }
        } else {
            int tenantId;

            try {
                tenantId = SAMLSSOAuthenticatorServiceComponent.getRealmService().getTenantManager()
                        .getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw new SAMLSSOException(
                        "Exception occurred while retrieving Tenant ID from tenant domain " +
                                tenantDomain, e);
            }

            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            PrivateKey key;

            try {
                /**
                 * Get the private key and the cert for the respective tenant domain.
                 */
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    // derive key store name
                    String ksName = tenantDomain.trim().replace(".", "-");
                    // derive JKS name
                    String jksName = ksName + ".jks";
                    key = (PrivateKey) keyStoreManager.getPrivateKey(jksName, tenantDomain);
                    cert = (X509Certificate) keyStoreManager.getKeyStore(jksName)
                            .getCertificate(tenantDomain);
                } else {
                    //key = keyStoreManager.getDefaultPrivateKey();
                    key = (PrivateKey) keyStoreManager.getDefaultPrivateKey();
                    cert = keyStoreManager.getDefaultPrimaryCertificate();

                }
            } catch (Exception e) {
                throw new SAMLSSOException(
                        "Error retrieving private key and the certificate for tenant " +
                                tenantDomain, e);
            }

            if (key == null) {
                throw new SAMLSSOException(
                        "Cannot find the private key for tenant " + tenantDomain);
            }

            this.privateKey = key;
        }

        if (cert == null) {
            throw new SAMLSSOException("Cannot find the certificate.");
        }

        entityCertificate = cert;
        publicKey = cert.getPublicKey();
    }

    /**
     * Retrieves the publicKey
     */
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public X509Certificate getEntityCertificate() {
        return entityCertificate;
    }

    // ********** Not implemented **************************************************************
    @Override
    public Collection<X509CRL> getCRLs() {
        return CollectionUtils.EMPTY_COLLECTION;
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        return Collections.emptySet();
    }

    @Override
    public CredentialContextSet getCredentalContextSet() {
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        return null;
    }

    @Override
    public String getEntityId() {
        return null;
    }

    @Override
    public Collection<String> getKeyNames() {
        return Collections.emptySet();
    }

    @Override
    public SecretKey getSecretKey() {
        return null;
    }

    @Override
    public UsageType getUsageType() {
        return null;
    }
}
