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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.internal;

import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.common.util.IdentityUtilService;

public class SAML2SSOAuthenticatorDataHolder {

    private static volatile SAML2SSOAuthenticatorDataHolder instance = new SAML2SSOAuthenticatorDataHolder();
    private IdentityUtilService identityUtilService = null;
    private X509Credential credential = null;

    private SAML2SSOAuthenticatorDataHolder() {

    }

    public static SAML2SSOAuthenticatorDataHolder getInstance() {
        return instance;
    }

    public void setIdentityUtilService(IdentityUtilService identityUtilService) {
        this.identityUtilService = identityUtilService;
    }

    public IdentityUtilService getIdentityUtilService() {
        return identityUtilService;
    }

    public void setCredential(X509Credential credential) {
        this.credential = credential;
    }

    public X509Credential getCredential() {
        return credential;
    }
}
