package org.wso2.carbon.identity.saml.outbound.test.module;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.identity.common.base.exception.IdentityException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

public class SAMLOutboundTestUtils {

    public static HttpURLConnection request(String path, String method, boolean keepAlive) throws IOException {

        URL url = new URL(path);

        HttpURLConnection httpURLConnection = null;

        httpURLConnection = (HttpURLConnection) url.openConnection();

        httpURLConnection.setRequestMethod(method);
        if (!keepAlive) {
            httpURLConnection.setRequestProperty("CONNECTION", "CLOSE");
        }
        return httpURLConnection;

    }

    public static String getContent(HttpURLConnection urlConn) throws IOException {
        return new String(IOUtils.toByteArray(urlConn.getInputStream()), Charsets.UTF_8);
    }

    public static String getResponseHeader(String headerName, HttpURLConnection urlConnection) {
        return ((HttpURLConnection) urlConnection).getHeaderField(headerName);
    }

    public static String getParameterFromHTML(String html, String startingTag, String endingTag) {
        if (StringUtils.isEmpty(html) || StringUtils.isEmpty(startingTag) || StringUtils.isEmpty(endingTag)) {
            return null;
        }
        String secondPart = html.split(startingTag)[1];
        if (StringUtils.isNotBlank(secondPart)) {
            return secondPart.split(endingTag)[0];
        }

        return null;
    }


    public static String getSAMLResponse() throws IdentityException {

        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(getIssuer());
        response.setID(createID());
        response.setDestination("https://localhost:9292/gateway");
        response.setStatus(buildStatus("urn:oasis:names:tc:SAML:2.0:status:Success", null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                + 100 * 60 * 1000L);
        response.setIssueInstant(issueInstant);
        //@TODO sessionHandling
        String sessionId = "";
        Assertion assertion = buildAssertion(notOnOrAfter);
        response.getAssertions().add(assertion);
        SAMLOutboundTestUtils.doSetSignature(response, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3" +
                ".org/2000/09/xmldsig#sha1", new SignKeyDataHolder());
        String respString = encode(marshall(response));
        return respString;
    }

    public static Assertion buildAssertion(DateTime notOnOrAfter) throws
            IdentityException {

        try {

            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();
            samlAssertion.setID(createID());
            samlAssertion.setVersion(SAMLVersion.VERSION_20);
            samlAssertion.setIssuer(getIssuer());
            samlAssertion.setIssueInstant(currentTime);
            Subject subject = new SubjectBuilder().buildObject();

            NameID nameId = new NameIDBuilder().buildObject();
            // TODO
            nameId.setValue("AuthenticatedUserName");

            nameId.setFormat(NameIdentifier.EMAIL);

            subject.setNameID(nameId);

            SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                    .buildObject();
            subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
            SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
            scData.setRecipient("http://localhost:8080/gateway");
            scData.setNotOnOrAfter(notOnOrAfter);
            subjectConfirmation.setSubjectConfirmationData(scData);
            subject.getSubjectConfirmations().add(subjectConfirmation);

//            if (samlResponseHandlerConfig.getRequestedRecipients() != null && samlResponseHandlerConfig
//                    .getRequestedRecipients().length
//                    > 0) {
//                for (String recipient : samlResponseHandlerConfig.getRequestedRecipients()) {
//                    subjectConfirmation = new SubjectConfirmationBuilder()
//                            .buildObject();
//                    subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
//                    scData = new SubjectConfirmationDataBuilder().buildObject();
//                    scData.setRecipient(recipient);
//                    scData.setNotOnOrAfter(notOnOrAfter);
//                    if (!context.isIdpInitSSO()) {
//                        scData.setInResponseTo(context.getId());
//                    }
//                    subjectConfirmation.setSubjectConfirmationData(scData);
//                    subject.getSubjectConfirmations().add(subjectConfirmation);
//                }
//            }

            samlAssertion.setSubject(subject);

            AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
            authStmt.setAuthnInstant(new DateTime());

            AuthnContext authContext = new AuthnContextBuilder().buildObject();
            AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
            authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
            authContext.setAuthnContextClassRef(authCtxClassRef);
            authStmt.setAuthnContext(authContext);
            samlAssertion.getAuthnStatements().add(authStmt);

            /*
                * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
                * the spec 2.0 the subject MUST be in the assertion
                */
//            Map<String, String> claims = SAMLSSOUtil.getAttributes(authenticationContext);
//            if (claims != null && !claims.isEmpty()) {
//                AttributeStatement attrStmt = buildAttributeStatement(claims);
//                if (attrStmt != null) {
//                    samlAssertion.getAttributeStatements().add(attrStmt);
//                }
//            }

            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                    .buildObject();
            Audience issuerAudience = new AudienceBuilder().buildObject();
//            issuerAudience.setAudienceURI(context.getIssuerWithDomain());
            audienceRestriction.getAudiences().add(issuerAudience);

            Audience audience = new AudienceBuilder().buildObject();
            audience.setAudienceURI("carbonServer");
            audienceRestriction.getAudiences().add(audience);

            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(currentTime);
            conditions.setNotOnOrAfter(notOnOrAfter);
            conditions.getAudienceRestrictions().add(audienceRestriction);
            samlAssertion.setConditions(conditions);

            SAMLOutboundTestUtils.doSetSignature(samlAssertion, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3" +
                    ".org/2000/09/xmldsig#sha1", new SignKeyDataHolder());

            return samlAssertion;
        } catch (Exception e) {
            System.out.println("");
        }
        return null;
    }

    public static String createID() {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
        }
        return null;
    }

    public static Issuer getIssuer() {
        Issuer issuer = new IssuerBuilder().buildObject();
        String idPEntityId = "localhost";
        issuer.setValue(idPEntityId);
        issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        return issuer;
    }

    public static String marshall(XMLObject xmlObject) {

        ByteArrayOutputStream byteArrayOutputStrm = null;
        try {
            doBootstrap();
            //            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
            //                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString(StandardCharsets.UTF_8.name());
        } catch (Exception e) {

        } finally {
            if (byteArrayOutputStrm != null) {
                try {
                    byteArrayOutputStrm.close();
                } catch (IOException e) {

                }
            }
        }
        return null;
    }

    public static void doBootstrap() {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
        }
    }

    public static String encode(String xmlString) {
        // Encoding the message
        String encodedRequestMessage =
                Base64.encodeBytes(xmlString.getBytes(StandardCharsets.UTF_8),
                        Base64.DONT_BREAK_LINES);
        return encodedRequestMessage.trim();
    }

    private static Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    public static X509CredentialImpl getX509CredentialImpl(String alias) {


        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        try {
            keyStoreManager = KeyStoreManager.getInstance();
            X509CredentialImpl credentialImpl = null;
            KeyStore keyStore;
            keyStore = keyStoreManager.getKeyStore();

            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
            credentialImpl = new X509CredentialImpl(cert);
            return credentialImpl;
        } catch (Exception e) {
        }
        return null;
    }

    private static SignableXMLObject doSetSignature(SignableXMLObject request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        doBootstrap();
        DefaultSSOSigner ssoSigner = new DefaultSSOSigner();

        return ssoSigner.setSignature(request, signatureAlgorithm, digestAlgorithm, cred);
    }

}
