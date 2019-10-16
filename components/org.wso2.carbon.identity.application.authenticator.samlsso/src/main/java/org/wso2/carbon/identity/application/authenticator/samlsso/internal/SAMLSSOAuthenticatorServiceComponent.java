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
package org.wso2.carbon.identity.application.authenticator.samlsso.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAMLSSOAuthenticator;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.processor.SAMLLogoutRequestProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.processor.SAMLRespBuildProcessor;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request.SAMLLogoutRequestFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.response.SAMLLogoutResponseFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.util.SAMLFedLogoutUtil;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="server.configuration.service"
 * interface="org.wso2.carbon.base.api.ServerConfigurationService"
 * cardinality="1..1" policy="dynamic" bind="setServerConfigurationService"
 * unbind="unsetServerConfigurationService"
 */
@Component(
         name = "identity.application.authenticator.samlsso.component", 
         immediate = true)
public class SAMLSSOAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(SAMLSSOAuthenticatorServiceComponent.class);

    private static String postPage = null;

    @Activate
    protected void activate(ComponentContext ctxt) {
        String postPagePath = null;
        FileInputStream fis = null;
        try {
            SAMLSSOAuthenticator samlSSOAuthenticator = new SAMLSSOAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), samlSSOAuthenticator, null);

            ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(), new
                    SAMLLogoutRequestFactory(), null);
            ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                    SAMLLogoutResponseFactory(), null);
            ctxt.getBundleContext()
                    .registerService(IdentityProcessor.class.getName(), new SAMLLogoutRequestProcessor(), null);
            ctxt.getBundleContext()
                    .registerService(IdentityProcessor.class.getName(), new SAMLRespBuildProcessor(), null);

            postPagePath = CarbonUtils.getCarbonHome() + File.separator + "repository" + File.separator + "resources" + File.separator + "identity" + File.separator + "pages" + File.separator + "samlsso_federate.html";
            fis = new FileInputStream(new File(postPagePath));
            postPage = new Scanner(fis, "UTF-8").useDelimiter("\\A").next();
            if (log.isDebugEnabled()) {
                log.info("SAML2 SSO Authenticator bundle is activated");
            }
        } catch (FileNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find SAMLSSO POST page for federation in " + postPagePath);
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed SAMLSSO authentication" + e);
            }
        } finally {
            IdentityIOStreamUtils.closeInputStream(fis);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.info("SAML2 SSO Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the SAML2 SSO Authenticator bundle");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the SAML2 SSO Authenticator bundle");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "ServerConfigurationService",
            service = org.wso2.carbon.base.api.ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService")
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {
        if (log.isDebugEnabled()) {
            log.debug("Set the ServerConfiguration Service");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {
        if (log.isDebugEnabled()) {
            log.debug("Unset the ServerConfiguration Service");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setServerConfigurationService(null);
    }

    public static String getPostPage() {
        return postPage;
    }
}

