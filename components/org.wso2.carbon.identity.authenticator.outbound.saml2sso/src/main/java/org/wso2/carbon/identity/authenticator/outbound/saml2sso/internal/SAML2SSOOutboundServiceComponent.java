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

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.authenticator.SAML2SSOAuthenticator;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.request.SAML2ACSRequestFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.response.SAML2SSOPostRequestResponseFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.response.SAML2SSORedirectRequestResponseFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.util.Utils;
import org.wso2.carbon.identity.common.base.exception.IdentityRuntimeException;
import org.wso2.carbon.identity.common.util.IdentityUtilService;
import org.wso2.carbon.identity.gateway.api.request.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.processor.authenticator.AbstractApplicationAuthenticator;

@Component(
        name = "outbound.saml2sso.dscomponent",
        service = SAML2SSOOutboundServiceComponent.class,
        immediate = true
)
public class SAML2SSOOutboundServiceComponent {

    private static Logger log = LoggerFactory.getLogger(SAML2SSOOutboundServiceComponent.class);

    @Activate
    protected void activate(BundleContext bundleContext) {

        try {
            doBootstrap();
            SAML2SSOAuthenticatorDataHolder.getInstance().setCredential(Utils.getServerCredentials());
            bundleContext.registerService(AbstractApplicationAuthenticator.class.getName(),
                                          new SAML2SSOAuthenticator(), null);
            bundleContext.registerService(AbstractApplicationAuthenticator.class,
                                          new SAML2SSOAuthenticator(), null);
            bundleContext.registerService(HttpIdentityRequestFactory.class, new SAML2ACSRequestFactory(), null);
            bundleContext.registerService(HttpIdentityResponseFactory.class, new SAML2SSOPostRequestResponseFactory(), null);
            bundleContext.registerService(HttpIdentityResponseFactory.class, new SAML2SSORedirectRequestResponseFactory(), null);
        } catch (Throwable e) {
            log.error("Error while registering SAML2SSOAuthenticator.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("SAML2SSOAuthenticator bundle is de-activated");
        }
    }

    @Reference(
            name = "identity.util.dscomponent",
            service = IdentityUtilService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityUtilService")
    protected void setIdentityUtilService(IdentityUtilService identityUtilService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the IdentityUtilService");
        }
        SAML2SSOAuthenticatorDataHolder.getInstance().setIdentityUtilService(identityUtilService);
    }

    protected void unsetIdentityUtilService(IdentityUtilService identityUtilService) {
        log.debug("UnSetting the IdentityUtilService");
        SAML2SSOAuthenticatorDataHolder.getInstance().setIdentityUtilService(null);
    }

    public static void doBootstrap() {

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(new SAML2SSOAuthenticator().getClass().getClassLoader());
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new IdentityRuntimeException("Error in bootstrapping the OpenSAML2 library", e);
        } finally {
            thread.setContextClassLoader(loader);
        }
    }
}