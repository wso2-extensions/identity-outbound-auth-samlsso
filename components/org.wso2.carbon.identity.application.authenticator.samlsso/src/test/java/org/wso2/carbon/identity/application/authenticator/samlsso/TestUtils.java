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
package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.KeyStore;

/**
 * Test util methods
 */
public class TestUtils {

    private TestUtils() {

    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf", fileName).toString();
        }
        return null;
    }

    public static KeyStore loadKeyStoreFromFileSystem(String keyStorePath, String password, String type) {

        try (FileInputStream inputStream = new FileInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            String errorMsg = "Error loading the key store from the given location.";
            throw new SecurityException(errorMsg, e);
        }
    }
}
