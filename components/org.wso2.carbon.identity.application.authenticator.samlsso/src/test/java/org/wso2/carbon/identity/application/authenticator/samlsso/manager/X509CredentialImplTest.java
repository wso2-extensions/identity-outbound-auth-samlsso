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

import org.apache.commons.collections.CollectionUtils;
import org.mockito.Mock;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.TestUtils;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceDataHolder;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.common.testng.TestConstants.CARBON_HOST_LOCALHOST;

/**
 * Unit tests for X509CredentialImpl.
 */
@PowerMockIgnore({"org.mockito.*","org.powermock.api.mockito.invocation.*"})
@PrepareForTest({KeyStoreManager.class, FrameworkUtils.class, KeystoreUtils.class})
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

    private X509Credential x509CredentialImpl;

    @BeforeClass
    public void initTest() throws Exception {

        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME))
                .thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(tenantManager.getTenantId(TestConstants.SAMPLE_TENANT_DOMAIN_NAME))
                .thenReturn(TestConstants.SAMPLE_TENANT_ID);

        keyStore = SSOUtils.loadKeyStoreFromFileSystem(TestUtils.getFilePath("wso2carbon.jks"),
                TestConstants.KEY_STORE_PASSWORD, "JKS");
        key = keyStore.getKey(TestConstants.KEY_ALIAS, TestConstants.KEY_PASSWORD.toCharArray());
        certificate = keyStore.getCertificate(TestConstants.KEY_ALIAS);

        x509CredentialImpl = new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                TestConstants.IDP_CERTIFICATE);
    }

    private void prepareForGetKeyStorePath() throws Exception {
        mockStatic(KeystoreUtils.class);
        when(KeystoreUtils.getKeyStoreFileLocation(TestConstants.SAMPLE_TENANT_DOMAIN_NAME)).thenReturn(
                TestUtils.getFilePath("wso2carbon.jks"));
    }

    @Test(priority = 1)
    public void testX509CredentialImplForSuperTenant() throws Exception {

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(superTenantKeyStoreManager);
        when(superTenantKeyStoreManager.getDefaultPrivateKey()).thenReturn((PrivateKey) key);
        when(superTenantKeyStoreManager.getDefaultPrimaryCertificate()).thenReturn((X509Certificate) certificate);

        X509Credential x509Credential = new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null);

        assertEquals(key, x509Credential.getPrivateKey(), "Failed to retrieve private key.");
        assertEquals(certificate.getPublicKey(), x509Credential.getPublicKey(),
                "Failed to retrieve public key.");
        assertEquals(certificate, x509Credential.getEntityCertificate(),
                "Failed to retrieve entire certificate.");
    }

    @Test(priority = 2)
    public void testX509CredentialImplForATenant() throws Exception {

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.START_TENANT_FLOW, TestConstants.SAMPLE_TENANT_DOMAIN_NAME);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(TestConstants.SAMPLE_TENANT_ID)).thenReturn(tenantKeyStoreManager);
        when(tenantKeyStoreManager.getPrivateKey(anyString(), anyString())).thenReturn(key);
        when(tenantKeyStoreManager.getKeyStore(anyString())).thenReturn(keyStore);
        keyStore.setCertificateEntry(TestConstants.SAMPLE_TENANT_DOMAIN_NAME, certificate);
        prepareForGetKeyStorePath();

        X509Credential x509Credential = new X509CredentialImpl(TestConstants.SAMPLE_TENANT_DOMAIN_NAME, "");

        assertEquals(key, x509Credential.getPrivateKey(), "Failed to retrieve private key.");
        assertEquals(certificate.getPublicKey(), x509Credential.getPublicKey(),
                "Failed to retrieve public key.");
        assertEquals(certificate, x509Credential.getEntityCertificate(),
                "Failed to retrieve entire certificate.");
    }

    @Test(priority = 3)
    public void testX509CredentialImplWithIdPCert() throws Exception {

        X509Credential x509Credential = new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,
                TestConstants.IDP_CERTIFICATE);

        assertEquals(certificate.getPublicKey(), x509Credential.getPublicKey(),
                "Failed to retrieve public key.");
        assertEquals(certificate, x509Credential.getEntityCertificate(),
                "Failed to retrieve entire certificate.");
    }

    @Test(priority = 4, expectedExceptions = SAMLSSOException.class)
    public void testX509CredentialImplWithInvalidIdPCert() throws Exception {

        new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, "Invalid certificate");
    }

    @Test(priority = 5, expectedExceptions = SAMLSSOException.class)
    public void testX509CredentialImplForInvalidTenant() throws Exception {

        when(tenantManager.getTenantId(TestConstants.INVALID_TENANT_DOMAIN)).thenThrow(new UserStoreException());

        new X509CredentialImpl(TestConstants.INVALID_TENANT_DOMAIN, null);
    }

    @Test(priority = 6, expectedExceptions = Exception.class)
    public void testX509CredentialImplWhenFailedToGetKeyStore() throws Exception {

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(TestConstants.SAMPLE_TENANT_ID)).thenReturn(tenantKeyStoreManager);
        when(tenantKeyStoreManager.getPrivateKey(anyString(), anyString())).thenReturn(key);
        when(tenantKeyStoreManager.getKeyStore(anyString())).thenThrow(new Exception());

        new X509CredentialImpl(TestConstants.SAMPLE_TENANT_DOMAIN_NAME, null);
    }

    @DataProvider(name = "exceptionGeneratingData")
    public Object[][] providerExceptionGeneratingData() {

        return new Object[][]{
                {null, certificate},
                {key, null}
        };
    }

    @Test(priority = 7, dataProvider = "exceptionGeneratingData", expectedExceptions = SAMLSSOException.class)
    public void testX509CredentialImplWhenKeyOrCertNull(Key key, Certificate certificate) throws Exception {

        mockStatic(FrameworkUtils.class);
        doNothing().when(FrameworkUtils.class, TestConstants.END_TENANT_FLOW);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(superTenantKeyStoreManager);
        when(superTenantKeyStoreManager.getDefaultPrivateKey()).thenReturn((PrivateKey) key);
        when(superTenantKeyStoreManager.getDefaultPrimaryCertificate()).thenReturn((X509Certificate) certificate);

        new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null);
    }

    @Test(priority = 8)
    public void getCRLs() {

        assertEquals(x509CredentialImpl.getCRLs(), CollectionUtils.EMPTY_COLLECTION, "Need to implement the " +
                "unit test.");
    }

    @Test(priority = 9)
    public void getEntityCertificateChain() {

        assertEquals(x509CredentialImpl.getEntityCertificateChain(), Collections.emptySet(), "Need to " +
                "implement the unit test.");
    }

    @Test(priority = 10)
    public void getCredentialContextSet() {

        assertNull(x509CredentialImpl.getCredentialContextSet(), "Need to implement the unit test.");
    }

    @Test(priority = 11)
    public void getCredentialType() {

        assertNull(x509CredentialImpl.getCredentialType(), "Need to implement the unit test.");
    }

    @Test(priority = 12)
    public void getEntityId() {

        assert CARBON_HOST_LOCALHOST.equals(x509CredentialImpl.getEntityId()) || ("").equals(x509CredentialImpl.getEntityId());
    }

    @Test(priority = 13)
    public void getKeyNames() {

        assertEquals(x509CredentialImpl.getKeyNames(), Collections.emptySet(), "Need to implement the unit test.");
    }

    @Test(priority = 14)
    public void getSecretKey() {

        assertNull(x509CredentialImpl.getSecretKey(), "Need to implement the unit test.");
    }

    @Test(priority = 15)
    public void getUsageType() {

        assertEquals(x509CredentialImpl.getUsageType(), UsageType.UNSPECIFIED);
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

}
