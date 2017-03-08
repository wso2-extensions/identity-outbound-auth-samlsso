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

package org.wso2.carbon.identity.saml.outbound.test.module;

import org.wso2.carbon.identity.common.base.exception.IdentityException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;

public class KeyStoreManager {

    private static KeyStoreManager instance = new KeyStoreManager();
    private KeyStore primaryKeyStore = null;


    private KeyStoreManager() {
        this.initKeyStore();
    }

    public static KeyStoreManager getInstance() {
        return instance;
    }

    public KeyStore getKeyStore() {
        return this.primaryKeyStore;
    }

    public Key getPrivateKey() throws IdentityException {
        KeyStore keyStore = getKeyStore();
        String alias = "wso2carbon";
        String keystorePassword = "wso2carbon";
        try {
            return keyStore.getKey(alias, keystorePassword.toCharArray());
        } catch (Exception e) {
            String msg = "Error has encountered while loading the key for the given alias " + alias;
            throw new IdentityException(msg);
        }
    }

    public KeyStore initKeyStore() {

        String keyStorePath = SAMLOutboundOSGiTestUtils.getCarbonHome() + File.separator + "resources" + File.separator
                + "security" + File.separator + "wso2carbon.jks";
        String keystorePassword = "wso2carbon";
        String keyStoreType = "JKS";

        if (this.primaryKeyStore == null) {
            FileInputStream in = null;
            try {
                KeyStore store = KeyStore.getInstance(keyStoreType);

                in = new FileInputStream(keyStorePath);
                store.load(in, keystorePassword.toCharArray());
                this.primaryKeyStore = store;
            } catch (Exception e) {
                throw new SecurityException("Error while reading key store from the given path");
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        throw new SecurityException("Error while reading key store");
                    }
                }
            }
        }

        return this.primaryKeyStore;
    }
}
