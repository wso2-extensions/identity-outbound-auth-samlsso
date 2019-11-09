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

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

/**
 * This class denotes exceptions thrown from the federated idp initiated SAML logout flow.
 */
public class SAMLIdentityException extends FrameworkException {

    private String acsUrl;
    private String relayState;
    private String exceptionMessage;

    public SAMLIdentityException(String errorDesciption) {

        super(errorDesciption);
    }

    public SAMLIdentityException(String message, Throwable cause) {

        super(message, cause);
    }

    public SAMLIdentityException(String errorDescription, String exceptionMessage, String acsUrl, String relayState) {

        super(errorDescription);
        this.acsUrl = acsUrl;
        this.relayState = relayState;
        this.exceptionMessage = exceptionMessage;
    }

    public static SAMLIdentityException error(String errorDescription, String exceptionMessage, String relayState,
                                              String acsUrl) {

        return new SAMLIdentityException(errorDescription, exceptionMessage, acsUrl, relayState);
    }

    public String getAcsUrl() {

        return acsUrl;
    }

    public String getRelayState() {

        return relayState;
    }

    public String getExceptionMessage() {

        return exceptionMessage;
    }
}
