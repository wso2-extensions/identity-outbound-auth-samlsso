/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.util;

import org.apache.commons.collections.CollectionUtils;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorException;

import java.security.PrivateKey;
import java.security.PublicKey;
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

    /**
     * Instantiates X509Credential.
     * If the IDP cert passed is not null the instantiated credential object will hold the passed
     * cert and the public key of the cert.
     * Otherwise the object will hold the private key, public key and the cert for the respective
     * tenant domain.
     */
    public X509CredentialImpl(X509Certificate certificate) {

        entityCertificate = certificate;
        publicKey = certificate.getPublicKey();
    }

    public X509CredentialImpl(X509Certificate certificate, PrivateKey privateKey) throws
                                                                                        SAML2SSOAuthenticatorException {
        this.entityCertificate = certificate;
        this.publicKey = certificate.getPublicKey();
        this.privateKey = privateKey;
    }

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

    @Override
    public CredentialContextSet getCredentalContextSet() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getEntityId() {
        // TODO Auto-generated method stub
        return null;
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
        // TODO Auto-generated method stub
        return null;
    }
}
