/*
 * Copyright (c) 2017-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.samlsso.internal;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * SAMLSSOAuthenticatorService Data Holder.
 */
public class SAMLSSOAuthenticatorServiceDataHolder {

    private static final SAMLSSOAuthenticatorServiceDataHolder INSTANCE = new SAMLSSOAuthenticatorServiceDataHolder();

    private RealmService realmService;
    private ServerConfigurationService serverConfigurationService;
    private OrganizationManager organizationManager;
    private ConfigurationManager configurationManager = null;

    public static SAMLSSOAuthenticatorServiceDataHolder getInstance() {

        return INSTANCE;
    }

    private SAMLSSOAuthenticatorServiceDataHolder() {
    }

    public RealmService getRealmService() {

        if(realmService == null) {
            throw new RuntimeException("RealmService is null.");
        }
        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public ServerConfigurationService getServerConfigurationService() {
        return serverConfigurationService;
    }

    public void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {
        this.serverConfigurationService = serverConfigurationService;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }
}
