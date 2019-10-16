package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;

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

    public static SAMLIdentityException error(String errorDescription, String exceptionMessage, String acsUrl, String relayState) {
        return new SAMLIdentityException(errorDescription, exceptionMessage, acsUrl, relayState);
    }

    public String getAcsUrl() { return acsUrl; }

    public String getRelayState() { return relayState; }

    public String getExceptionMessage() {
        return exceptionMessage;
    }

}
