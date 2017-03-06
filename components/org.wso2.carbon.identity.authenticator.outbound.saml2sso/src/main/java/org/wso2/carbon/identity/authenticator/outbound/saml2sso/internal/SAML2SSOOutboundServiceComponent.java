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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.authenticator.SAML2SSOAuthenticator;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.request.SAML2ACSRequestBuilderFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.response.SAML2SSOPostRequestResponseBuilderFactory;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.response.SAML2SSORedirectRequestResponseBuilderFactory;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequestBuilderFactory;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;
import org.wso2.carbon.identity.gateway.authentication.authenticator.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.gateway.authentication.authenticator.ApplicationAuthenticator;

/**
 * SAML2 SSO Outbound Authenticator Service Component.
 */
@Component(
        name = "outbound.saml2sso.dscomponent",
        service = SAML2SSOOutboundServiceComponent.class,
        immediate = true
)
public class SAML2SSOOutboundServiceComponent {

    private static Logger logger = LoggerFactory.getLogger(SAML2SSOOutboundServiceComponent.class);

    @Activate
    protected void activate(BundleContext bundleContext) {

        try {
            doBootstrap();
            // why do we need to register two times
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), new SAML2SSOAuthenticator(), null);
            bundleContext.registerService(AbstractApplicationAuthenticator.class, new SAML2SSOAuthenticator(), null);
            bundleContext.registerService(GatewayRequestBuilderFactory.class, new SAML2ACSRequestBuilderFactory(),
                                          null);
            bundleContext.registerService(GatewayResponseBuilderFactory.class,
                                          new SAML2SSOPostRequestResponseBuilderFactory(), null);
            bundleContext.registerService(GatewayResponseBuilderFactory.class,
                                          new SAML2SSORedirectRequestResponseBuilderFactory(), null);
        } catch (Throwable e) {
            logger.error("Error while registering SAML2SSOAuthenticator.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (logger.isDebugEnabled()) {
            logger.debug("SAML2SSOAuthenticator bundle is de-activated.");
        }
    }

    private void doBootstrap() {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            logger.error("Error in bootstrapping the OpenSAML2 library.", e);
        }
    }
}
