package org.wso2.carbon.identity.application.authenticator.samlsso.logout.validators;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.Test;
import org.mockito.Mock;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.context.SAMLMessageContext;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.exception.SAMLIdentityException;

import static org.junit.Assert.*;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.IDP_CERTIFICATE;
import static org.wso2.carbon.identity.application.authenticator.samlsso.TestConstants.QUERY_STRING;
import static org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants.CERTIFICATE_TYPE;

public class LogoutReqSignatureValidatorTest {

    LogoutReqSignatureValidator validator =new LogoutReqSignatureValidator();

    @Test
    public void validateSignature() throws Exception{
        X509Certificate x509Certificate = generateX509Certificate(IDP_CERTIFICATE);
        validator.validateSignature(QUERY_STRING,"localhost", x509Certificate);
    }

    @Test
    public void validateXMLSignature() {

    }

    private static X509Certificate generateX509Certificate(String certificate)
            throws SAMLIdentityException {

        byte[] certificateData = java.util.Base64.getDecoder().decode(certificate);
        try {
            return (java.security.cert.X509Certificate) CertificateFactory.getInstance(CERTIFICATE_TYPE).
                    generateCertificate(new ByteArrayInputStream(certificateData));
        } catch (CertificateException e) {
            throw new SAMLIdentityException("Error occurred while generating X509Certificate using the " +
                    "string value of the certificate in IdP's properties: " + certificate, e);
        }
    }
}