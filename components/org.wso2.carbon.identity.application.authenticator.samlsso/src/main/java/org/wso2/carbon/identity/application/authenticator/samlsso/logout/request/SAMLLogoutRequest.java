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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.request;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class  holds the necessary parameters of the HTTPServletRequest.
 * SAMLLogoutRequestBuilder is an inner class of this class and it is responsible
 * for building a concrete instance of SAMLLogoutRequest for the framework when needed.
 */
public class SAMLLogoutRequest extends IdentityRequest {

    private boolean isPost;

    protected SAMLLogoutRequest(SAMLLogoutRequestBuilder builder) throws FrameworkClientException {

        super(builder);
        this.isPost = builder.isPost;
    }

    public boolean isPost() {

        return isPost;
    }

    public static class SAMLLogoutRequestBuilder extends IdentityRequestBuilder {

        private boolean isPost;

        public SAMLLogoutRequestBuilder(HttpServletRequest request, HttpServletResponse response) {

            super(request, response);
        }

        public SAMLLogoutRequestBuilder isPost(boolean isPost) {

            this.isPost = isPost;
            return this;
        }

        @Override
        public SAMLLogoutRequest build() throws FrameworkClientException {

            return new SAMLLogoutRequest(this);
        }
    }
}
