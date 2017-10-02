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
package org.wso2.carbon.identity.application.authenticator.samlsso.manager;

import org.mockito.Mock;
import org.opensaml.xml.security.x509.X509Credential;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit tests for X509CredentialImpl.
 */
@PrepareForTest(KeyStoreManager.class)
public class X509CredentialImplTest {

    @Mock
    private RealmService realmService;

    @Mock
    private KeyStoreManager superTenantKeyStoreManager;

    @Mock
    private KeyStoreManager tenantKeyStoreManager;

    @Mock
    private TenantManager tenantManager;

    private KeyStore keyStore;

    private Key key;

    private Certificate certificate;

    @BeforeClass
    public void initTest() throws Exception {

        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(tenantManager.getTenantId(TestConstants.SAMPLE_TENANT_DOMAIN_NAME))
                .thenReturn(TestConstants.SAMPLE_TENANT_ID);

        keyStore = TestUtils.loadKeyStoreFromFileSystem(TestUtils.getFilePath("wso2carbon.jks"),
                TestConstants.KEY_STORE_PASSWORD, "JKS");
        key = keyStore.getKey(TestConstants.KEY_ALIAS, TestConstants.KEY_PASSWORD.toCharArray());
        certificate = keyStore.getCertificate(TestConstants.KEY_ALIAS);
    }

    @Test(priority = 1)
    public void testX509CredentialImplForSuperTenant() throws Exception {

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(superTenantKeyStoreManager);
        when(superTenantKeyStoreManager.getDefaultPrivateKey()).thenReturn((PrivateKey) key);
        when(superTenantKeyStoreManager.getDefaultPrimaryCertificate()).thenReturn((X509Certificate) certificate);

        X509Credential x509Credential = new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null);

        Assert.assertEquals(key, x509Credential.getPrivateKey(), "Failed to retrieve private key.");
        Assert.assertEquals(certificate.getPublicKey(), x509Credential.getPublicKey(),
                "Failed to retrieve public key.");
        Assert.assertEquals(certificate, x509Credential.getEntityCertificate(),
                "Failed to retrieve entire certificate.");
    }

    @Test(priority = 2)
    public void testX509CredentialImplForATenant() throws Exception {

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(TestConstants.SAMPLE_TENANT_ID)).thenReturn(tenantKeyStoreManager);
        when(tenantKeyStoreManager.getPrivateKey(anyString(), anyString())).thenReturn(key);
        when(tenantKeyStoreManager.getKeyStore(anyString())).thenReturn(keyStore);
        keyStore.setCertificateEntry(TestConstants.SAMPLE_TENANT_DOMAIN_NAME, certificate);

        X509Credential x509Credential = new X509CredentialImpl(TestConstants.SAMPLE_TENANT_DOMAIN_NAME, null);

        Assert.assertEquals(key, x509Credential.getPrivateKey(), "Failed to retrieve private key.");
        Assert.assertEquals(certificate.getPublicKey(), x509Credential.getPublicKey(),
                "Failed to retrieve public key.");
        Assert.assertEquals(certificate, x509Credential.getEntityCertificate(),
                "Failed to retrieve entire certificate.");
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
