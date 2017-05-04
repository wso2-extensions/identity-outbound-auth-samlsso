/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.core.KeyProviderService;

import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Provide the default implementation to fetch the tenant specific private key.
 * This default implementation is used if there isn't any other implementation
 * registered as an OSGi service.
 */

public class DefaultKeyProvider implements KeyProviderService {

    @Override
    public Key getPrivateKey(String tenantDomain) throws SAMLSSOException {
        Key privateKey;

        try {
            int tenantId = SAMLSSOAuthenticatorServiceComponent.getRealmService().
                    getTenantManager().getTenantId(tenantDomain);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                // derive JKS name
                String jksName = ksName + ".jks";
                privateKey = (PrivateKey) keyStoreManager.getPrivateKey(jksName, tenantDomain);

            } else {
                privateKey = keyStoreManager.getDefaultPrivateKey();
            }
        } catch (Exception e) {
            throw new SAMLSSOException(
                    "Error retrieving private key for tenant " + tenantDomain, e);
        }
        return privateKey;
    }

    @Override
    public Certificate getCertificate(String s) throws Exception {
        return null;
    }
}
