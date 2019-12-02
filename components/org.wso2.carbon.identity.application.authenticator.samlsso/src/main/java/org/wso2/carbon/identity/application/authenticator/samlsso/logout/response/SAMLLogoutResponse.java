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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.response;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;

/**
 * This class  holds the necessary parameters for building the HTTPServletResponse.
 * <p>
 * SAMLLogoutResponseBuilder is an inner class of this class and it is responsible
 * or building a concrete instance of SAMLLogoutResponse for the framework when needed.
 */
public class SAMLLogoutResponse extends IdentityResponse {

    private String response;
    private String acsUrl;
    private String relayState;

    protected SAMLLogoutResponse(IdentityResponseBuilder builder) {

        super(builder);
        SAMLLogoutResponseBuilder responsebuilder = (SAMLLogoutResponseBuilder) builder;
        this.response = responsebuilder.response;
        this.acsUrl = responsebuilder.acsUrl;
        this.relayState = responsebuilder.relayState;
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

        private String response;
        private String acsUrl;
        private String relayState;

        public SAMLLogoutResponseBuilder(SAMLMessageContext context) {

            super(context);
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
