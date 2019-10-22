/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.response;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedIdpInitLogout.context.SAMLMessageContext;

/**
 * This class  holds the necessary parameters for building the HTTPServletResponse.
 * SAMLLogoutResponseBuilder is an inner class of this class and it is responsible
 * or building a concrete instance of SAMLLogoutResponse for the framework when needed.
 */
public class SAMLLogoutResponse extends IdentityResponse {

    protected SAMLMessageContext context;
    protected String response;
    protected String acsUrl;
    protected String relayState;

    protected SAMLLogoutResponse(IdentityResponseBuilder builder) {

        super(builder);
        this.context = ((SAMLLogoutResponseBuilder) builder).context;
        this.response = ((SAMLLogoutResponseBuilder) builder).response;
        this.acsUrl = ((SAMLLogoutResponseBuilder) builder).acsUrl;
        this.relayState = ((SAMLLogoutResponseBuilder) builder).relayState;
    }

    public String getResponse() {
        return response;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getRelayState() {
        return relayState;
    }

    public static class SAMLLogoutResponseBuilder extends IdentityResponseBuilder {

        protected SAMLMessageContext context;
        protected String response;
        protected String acsUrl;
        protected String relayState;

        public SAMLLogoutResponseBuilder(SAMLMessageContext context) {
            this.context = context;
        }

        @Override
        public SAMLLogoutResponse build() {
            return new SAMLLogoutResponse(this);
        }

        public SAMLLogoutResponseBuilder setResponse(String response) {

            this.response = response;
            return this;
        }

        public SAMLLogoutResponseBuilder setAcsUrl(String acsUrl) {

            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLLogoutResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }
    }
}
