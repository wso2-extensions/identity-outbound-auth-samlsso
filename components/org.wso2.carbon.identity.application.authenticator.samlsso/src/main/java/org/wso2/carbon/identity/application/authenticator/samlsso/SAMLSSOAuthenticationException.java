package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.wso2.carbon.identity.application.authentication.framework.processor.handler.authentication
        .AuthenticationHandlerException;

/**
 * Created by harsha on 5/20/16.
 */
public class SAMLSSOAuthenticationException extends AuthenticationHandlerException{
    public SAMLSSOAuthenticationException(String message) {
        super(message);
    }

    public SAMLSSOAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
