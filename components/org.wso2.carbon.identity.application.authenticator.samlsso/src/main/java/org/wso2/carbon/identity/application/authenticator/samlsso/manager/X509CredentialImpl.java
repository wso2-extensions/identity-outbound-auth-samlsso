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
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
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

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private X509Certificate entityCertificate = null;
    private String entityId = StringUtils.EMPTY;

    private static KeyStore superTenantSignKeyStore = null;
    private static final Log log = LogFactory.getLog(X509CredentialImpl.class);

    public static final String SECURITY_SAML_SIGN_KEY_STORE_LOCATION = "Security.SAMLSignKeyStore.Location";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_TYPE = "Security.SAMLSignKeyStore.Type";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_PASSWORD = "Security.SAMLSignKeyStore.Password";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS = "Security.SAMLSignKeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD = "Security.SAMLSignKeyStore.KeyPassword";

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
     */
    public X509CredentialImpl(String tenantDomain, String idpCert) throws SAMLSSOException {

        X509Certificate cert;

        /**
         * If IDP cert is passed as a parameter set the cert to the IDP cert.
         * IDP cert should be passed when used with response validation.
         */
        if (idpCert != null && !idpCert.isEmpty()) {
            try {
                cert = (X509Certificate) IdentityApplicationManagementUtil
                        .decodeCertificate(idpCert);
            } catch (CertificateException e) {
                throw new SAMLSSOException(ErrorMessages.RETRIEVING_THE_CERTIFICATE_FAILED.getCode(),
                        String.format("Error retrieving the certificate for alias %s", idpCert), e);
            }
        } else {
            int tenantId;

            try {
                tenantId = SAMLSSOAuthenticatorServiceDataHolder.getInstance().getRealmService().getTenantManager()
                        .getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw new SAMLSSOException(ErrorMessages.RETRIEVING_TENANT_ID_FAILED.getCode(),
                        String.format(ErrorMessages.RETRIEVING_TENANT_ID_FAILED.getMessage(), tenantDomain), e);
            }

            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            PrivateKey key;

            try {
                /**
                 * Get the private key and the cert for the respective tenant domain.
                 */
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    FrameworkUtils.startTenantFlow(tenantDomain);
                    String fileName = KeystoreUtils.getKeyStoreFileLocation(tenantDomain);
                    key =
                            (PrivateKey) keyStoreManager.getPrivateKey(fileName, tenantDomain);
                    cert = (X509Certificate) keyStoreManager.getKeyStore(fileName)
                            .getCertificate(tenantDomain);
                } else {
                    if (isSignKeyStoreConfigured()) {
                        if (log.isDebugEnabled()) {
                            log.debug("Initializing Key Data for super tenant using separate sign key store");
                        }

                        try {
                            if (superTenantSignKeyStore == null) {

                                String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                                        SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
                                try (FileInputStream is = new FileInputStream(keyStoreLocation)) {
                                    String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                                            SECURITY_SAML_SIGN_KEY_STORE_TYPE);
                                    KeyStore keyStore = KeyStore.getInstance(keyStoreType);

                                    char[] keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                                            SECURITY_SAML_SIGN_KEY_STORE_PASSWORD).toCharArray();
                                    keyStore.load(is, keyStorePassword);

                                    superTenantSignKeyStore = keyStore;
                                } catch (FileNotFoundException e) {
                                    throw new SAMLSSOException(ErrorMessages.UNABLE_TO_LOCATE_KEYSTORE.getCode(),
                                            ErrorMessages.UNABLE_TO_LOCATE_KEYSTORE.getMessage(), e);
                                } catch (IOException e) {
                                    throw new SAMLSSOException(ErrorMessages.UNABLE_TO_READ_KEYSTORE.getCode(),
                                            ErrorMessages.UNABLE_TO_READ_KEYSTORE.getMessage(), e);
                                } catch (CertificateException e) {
                                    throw new SAMLSSOException(ErrorMessages.UNABLE_TO_READ_CERTIFICATE.getCode(),
                                            ErrorMessages.UNABLE_TO_READ_CERTIFICATE.getMessage(), e);
                                }
                            }

                            String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                                    SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
                            char[] keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                                    SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD).toCharArray();
                            Key privateKey = superTenantSignKeyStore.getKey(keyAlias, keyPassword);

                            Certificate publicKey = superTenantSignKeyStore.getCertificate(keyAlias);

                            if (privateKey instanceof PrivateKey) {
                                key = (PrivateKey) privateKey;
                            } else {
                                throw new SAMLSSOException(
                                        ErrorMessages.CONFIGURED_PRIVATE_KEY_IS_INVALID.getCode(),
                                        ErrorMessages.CONFIGURED_PRIVATE_KEY_IS_INVALID.getMessage());
                            }

                            if (publicKey instanceof X509Certificate) {
                                cert = (X509Certificate) publicKey;
                            } else {
                                throw new SAMLSSOException(
                                        ErrorMessages.CONFIGURED_PUBLIC_KEY_IS_INVALID.getCode(),
                                        ErrorMessages.CONFIGURED_PUBLIC_KEY_IS_INVALID.getMessage());
                            }

                        } catch (NoSuchAlgorithmException e) {
                            throw new SAMLSSOException(ErrorMessages.INVALID_ALGORITHM.getCode(),
                                    ErrorMessages.INVALID_ALGORITHM.getMessage(), e);
                        } catch (UnrecoverableKeyException e) {
                            throw new SAMLSSOException(ErrorMessages.UNABLE_TO_LOAD_KEY.getCode(),
                                    ErrorMessages.UNABLE_TO_LOAD_KEY.getMessage(), e);
                        } catch (KeyStoreException e) {
                            throw new SAMLSSOException(ErrorMessages.UNABLE_TO_LOAD_KEYSTORE.getCode(),
                                    ErrorMessages.UNABLE_TO_LOAD_KEYSTORE.getMessage(), e);
                        }
                    } else {
                        key = keyStoreManager.getDefaultPrivateKey();
                        cert = keyStoreManager.getDefaultPrimaryCertificate();
                    }
                }
            } catch (Exception e) {
                throw new SAMLSSOException(
                        ErrorMessages.RETRIEVING_PRIVATE_KEY_AND_CERTIFICATE_FOR_TENANT_FAILED.getCode(), String.format(
                        ErrorMessages.RETRIEVING_PRIVATE_KEY_AND_CERTIFICATE_FOR_TENANT_FAILED.getMessage(),
                        tenantDomain), e);
            } finally {
                if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    FrameworkUtils.endTenantFlow();
                }
            }

            if (key == null) {
                throw new SAMLSSOException(ErrorMessages.CANNOT_FIND_THE_PRIVATE_KEY_FOR_TENANT.getCode(),
                        String.format(ErrorMessages.CANNOT_FIND_THE_PRIVATE_KEY_FOR_TENANT.getMessage(), tenantDomain));
            }

            this.privateKey = key;
        }

        if (cert == null) {
            throw new SAMLSSOException(ErrorMessages.CANNOT_FIND_THE_CERTIFICATE.getCode(),
                    ErrorMessages.CANNOT_FIND_THE_CERTIFICATE.getMessage());
        }

        entityCertificate = cert;
        publicKey = cert.getPublicKey();
    }

    /**
     * Constructor.
     *
     * @param certificate Certificate of the IDP.
     * @param entityId    Entity Id of the credential.
     */
    public X509CredentialImpl(X509Certificate certificate, String entityId) {

        publicKey = certificate.getPublicKey();
        this.entityId = entityId;
    }

    /**
     * Check whether separate configurations for sign KeyStore available
     *
     * @return true if necessary configurations are defined for sign KeyStore; false otherwise.
     */
    private boolean isSignKeyStoreConfigured() {
        String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
        String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_TYPE);
        String keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_PASSWORD);
        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
        String keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD);

        return StringUtils.isNotBlank(keyStoreLocation) && StringUtils.isNotBlank(keyStoreType)
                && StringUtils.isNotBlank(keyStorePassword) && StringUtils.isNotBlank(keyAlias)
                && StringUtils.isNotBlank(keyPassword);
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
        // TODO Auto-generated method stub
        return CollectionUtils.EMPTY_COLLECTION;
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        // TODO Auto-generated method stub
        return Collections.emptySet();
    }

    /***
     * Get the credential context set.
     * @return This method is not supported so the return is null.
     */
    @Override
    public CredentialContextSet getCredentialContextSet() {
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getEntityId() {

        return entityId;
    }

    @Override
    public Collection<String> getKeyNames() {
        // TODO Auto-generated method stub
        return Collections.emptySet();
    }

    @Override
    public SecretKey getSecretKey() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public UsageType getUsageType() {

        return UsageType.UNSPECIFIED;
    }
}
