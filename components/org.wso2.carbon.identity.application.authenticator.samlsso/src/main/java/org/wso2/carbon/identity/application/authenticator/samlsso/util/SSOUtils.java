/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.application.authenticator.samlsso.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidationProvider;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class SSOUtils {
    private SSOUtils() {

    }

    private static final Log log = LogFactory.getLog(SSOUtils.class);

    /**
     * Generates a unique Id for Authentication Requests
     *
     * @return generated unique ID
     */

    public static String createID() {
        RandomIdentifierGenerationStrategy generator = new RandomIdentifierGenerationStrategy();
        return generator.generateIdentifier();
    }

    /**
     * Sign the SAML Request message
     * 
     * @param request
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param includeCert
     * @param x509Credential
     * @return
     * @throws SAMLSSOException
     */
    public static void setSignature(RequestAbstractType request, String signatureAlgorithm,
            String digestAlgorithm, boolean includeCert, X509Credential x509Credential)
            throws SAMLSSOException {
        
        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null");
        }
        if (x509Credential == null) {
            throw new IllegalArgumentException("X509Credential cannot be null");
        }
        if (x509Credential.getEntityCertificate() == null) {
            throw new SAMLSSOException(
                    "IdP certificate is needed for AuthnRequest signing in POST binding");
        }
        //TODO use StringUtils.isBlank
        if (StringUtils.isEmpty(signatureAlgorithm)) {
            signatureAlgorithm = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(
                    IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1);
        }
        if (StringUtils.isEmpty(digestAlgorithm)) {
            digestAlgorithm = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(
                    IdentityApplicationConstants.XML.DigestAlgorithm.SHA1);
        }
        
        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(x509Credential);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        if (includeCert) {
                KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
                X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
                org.opensaml.xmlsec.signature.X509Certificate cert = (org.opensaml.xmlsec.signature.X509Certificate) buildXMLObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
                String value = null;
                try {
                    value = org.apache.xml.security.utils.Base64.encode(x509Credential
                            .getEntityCertificate().getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new SAMLSSOException("Error getting the certificate to include in the signature", e);
                }
                cert.setValue(value);
                data.getX509Certificates().add(cert);
                keyInfo.getX509Datas().add(data);
                signature.setKeyInfo(keyInfo);
        }

        request.setSignature(signature);
        ((SAMLObjectContentReference)signature.getContentReferences().get(0))
              .setDigestAlgorithm(digestAlgorithm);
        
        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);

        // Marshall and Sign
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
        try {
            marshaller.marshall(request);
        } catch (MarshallingException e) {
            throw new SAMLSSOException("Error while marshalling the SAML Request for signing", e);
        }

        org.apache.xml.security.Init.init();
        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(SignatureValidationProvider.class.getClassLoader());
        try {
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            throw new SAMLSSOException("Error while signing the SAML Request", e);
        } finally {
            thread.setContextClassLoader(loader);
        }
    }

  public static void addSignatureToHTTPQueryString(StringBuilder httpQueryString,
            String signatureAlgorithmURI, X509Credential credential) throws SAMLSSOException {
        try {
			httpQueryString.append("&SigAlg=");
            httpQueryString
                    .append(URLEncoder.encode(signatureAlgorithmURI, "UTF-8").trim());

            byte[] rawSignature = XMLSigningUtil.signWithURI(credential, signatureAlgorithmURI,
                    httpQueryString.toString().getBytes("UTF-8"));

            String base64Signature = new String(Base64.encodeBase64(rawSignature, false));

            if (log.isDebugEnabled()) {
                log.debug("Generated digital signature value (base64-encoded) {} " + base64Signature);
            }

            httpQueryString.append("&Signature=" + URLEncoder.encode(base64Signature, "UTF-8").trim());

        } catch (SecurityException e) {
            throw new SAMLSSOException("Unable to sign query string", e);
        } catch (UnsupportedEncodingException e) {
            // UTF-8 encoding is required to be supported by all JVMs
            throw new SAMLSSOException("Error while adding signature to HTTP query string", e);
        }
  }

    /**
     * Builds SAML Elements
     *
     * @param objectQName
     * @return
     * @throws SAMLSSOException
     */
    private static XMLObject buildXMLObject(QName objectQName) throws SAMLSSOException {
        XMLObjectBuilder builder = XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(objectQName);
        if (builder == null) {
            throw new SAMLSSOException("Unable to retrieve builder for object QName " +
                    objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }

    /**
     * Decoding and deflating the encoded AuthReq
     *
     * @param encodedStr encoded AuthReq
     * @return decoded AuthReq
     */
    public static String decode(String encodedStr) throws SAMLSSOException {
        try {
            if(log.isDebugEnabled()){
                log.debug(" >> encoded string in the SSOUtils/decode : " + encodedStr);
            }
            org.apache.commons.codec.binary.Base64 base64Decoder =
                    new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            try {
                //TODO if the request came in POST, inflating is wrong
                Inflater inflater = new Inflater(true);
                inflater.setInput(base64DecodedByteArray);
                byte[] xmlMessageBytes = new byte[5000];
                int resultLength = inflater.inflate(xmlMessageBytes);

                if (!inflater.finished() ){
                    throw new RuntimeException("End of the compressed data stream has NOT been reached");
                }

                inflater.end();
                String decodedString = new String(xmlMessageBytes, 0, resultLength, "UTF-8");
                if (log.isDebugEnabled()) {
                    log.debug("Request message " + decodedString);
                }
                return decodedString;

            } catch (DataFormatException e) {
                ByteArrayInputStream bais = new ByteArrayInputStream(base64DecodedByteArray);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InflaterInputStream iis = new InflaterInputStream(bais);
                byte[] buf = new byte[1024];
                int count = iis.read(buf);
                while (count != -1) {
                    baos.write(buf, 0, count);
                    count = iis.read(buf);
                }
                iis.close();
                String decodedStr = new String(baos.toByteArray(), Charset.forName("UTF-8"));
                if (log.isDebugEnabled()) {
                    log.debug("Request message " + decodedStr);
                }
                return decodedStr;
            }
        } catch (IOException e) {
            throw new SAMLSSOException("Error when decoding the SAML Request.", e);
        }

    }

    public static String decodeForPost(String encodedStr)
            throws SAMLSSOException {
        try {
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            String decodedString = new String(base64DecodedByteArray, "UTF-8");
            if (log.isDebugEnabled()) {
                log.debug("Request message " + decodedString);
            }
            return decodedString;

        } catch (IOException e) {
            throw new SAMLSSOException(
                    "Error when decoding the SAML Request.", e);
        }
    }

    /**
     * Serializing a SAML2 object into a String
     *
     * @param xmlObject object that needs to serialized.
     * @return serialized object
     * @throws SAMLSSOException
     */
    public static String marshall(XMLObject xmlObject) throws SAMLSSOException {
        try {

            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString();
        } catch (Exception e) {
            log.error("Error Serializing the SAML Response");
            throw new SAMLSSOException("Error Serializing the SAML Response", e);
        }
    }

    /**
     * Unmarshalling a String into a SAML2 object
     *
     * @param samlString marshalled String
     * @return unmarshalled object
     * @throws SAMLSSOException
     */
    public static XMLObject unmarshall(String samlString) throws SAMLSSOException {

        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());

        try {
            InitializationService.initialize();

            org.opensaml.saml.config.SAMLConfigurationInitializer initializer_1 = new org.opensaml.saml.config.SAMLConfigurationInitializer();
            initializer_1.init();

            org.opensaml.saml.config.XMLObjectProviderInitializer initializer_2 = new org.opensaml.saml.config.XMLObjectProviderInitializer();
            initializer_2.init();

            org.opensaml.core.xml.config.XMLObjectProviderInitializer initializer_3 = new org.opensaml.core.xml.config.XMLObjectProviderInitializer();
            initializer_3.init();

            org.opensaml.core.xml.config.GlobalParserPoolInitializer initializer_4 = new org.opensaml.core.xml.config.GlobalParserPoolInitializer();
            initializer_4.init();

            org.opensaml.xmlsec.config.JavaCryptoValidationInitializer initializer_5 = new org.opensaml.xmlsec.config.JavaCryptoValidationInitializer();
            initializer_5.init();

            org.opensaml.xmlsec.config.XMLObjectProviderInitializer initializer_6 = new org.opensaml.xmlsec.config.XMLObjectProviderInitializer();
            initializer_6.init();

            org.opensaml.xmlsec.config.ApacheXMLSecurityInitializer initializer_7 = new org.opensaml.xmlsec.config.ApacheXMLSecurityInitializer();
            initializer_7.init();

            org.opensaml.xmlsec.config.GlobalSecurityConfigurationInitializer initializer_8 = new org.opensaml.xmlsec.config.GlobalSecurityConfigurationInitializer();
            initializer_8.init();

            org.opensaml.xmlsec.config.GlobalAlgorithmRegistryInitializer initializer_9 = new org.opensaml.xmlsec.config.GlobalAlgorithmRegistryInitializer();
            initializer_9.init();

        } catch (InitializationException e) {
            e.printStackTrace();
        } finally {
            thread.setContextClassLoader(loader);
        }

        try {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            documentBuilderFactory.setIgnoringComments(true);
            Document document = getDocument(documentBuilderFactory, samlString);
            if (isSignedWithComments(document)) {
                documentBuilderFactory.setIgnoringComments(false);
                document = getDocument(documentBuilderFactory, samlString);
            }
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (ParserConfigurationException | UnmarshallingException | SAXException | IOException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        }

    }

    /**
     * Encoding the response
     *
     * @param xmlString String to be encoded
     * @return encoded String
     */
    public static String encode(String xmlString) {
//        String encodedRequestMessage = Base64Support.encode(xmlString.getBytes(), Base64Support.UNCHUNKED);
        String encodedRequestMessage = new String(org.apache.commons.codec.binary.Base64.encodeBase64(xmlString.getBytes(), false));
        return encodedRequestMessage.trim();
    }

    public static boolean isAuthnRequestSigned(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isLogoutEnabled(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isLogoutRequestSigned(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isAuthnResponseSigned(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isAssertionSigningEnabled(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_SIGNING);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isAssertionEncryptionEnabled(Map<String, String> properties) {
        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_ENCRYPTION);
            if (prop != null) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isArtifactResolveReqSigningEnabled(Map<String, String> properties) {

        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ARTIFACT_RESOLVE_REQ_SIGNED);
            if (StringUtils.isNotBlank((prop))) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static boolean isArtifactResponseSigningEnabled(Map<String, String> properties) {

        if (properties != null) {
            String prop = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ARTIFACT_RESPONSE_SIGNED);
            if (StringUtils.isNotBlank((prop))) {
                return Boolean.parseBoolean(prop);
            }
        }
        return false;
    }

    public static String getArtifactResolveUrl(Map<String, String> properties) {

        String artifactResolveUrl = null;
        if (properties != null) {
            artifactResolveUrl = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.ARTIFACT_RESOLVE_URL);
            if (log.isDebugEnabled()) {
                log.debug("Artifact Resolution Service Url: " + artifactResolveUrl);
            }
        }
        return artifactResolveUrl;
    }

    public static String getSignatureAlgorithm(Map<String, String> properties) {

        String signatureAlgo = null;
        if (properties != null) {
            signatureAlgo = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        }
        if (StringUtils.isEmpty(signatureAlgo)) {
            signatureAlgo = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
        }
        signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(signatureAlgo);
        if (log.isDebugEnabled()) {
            log.debug("Signature Algorithm: " + signatureAlgo);
        }
        return signatureAlgo;
    }

    public static String getDigestAlgorithm(Map<String, String> properties) {

        String digestAlgo = null;
        if (properties != null) {
            digestAlgo = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        }
        if (StringUtils.isEmpty(digestAlgo)) {
            digestAlgo = IdentityApplicationConstants.XML.DigestAlgorithm.SHA1;
        }
        digestAlgo = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(digestAlgo);
        if (log.isDebugEnabled()) {
            log.debug("Digest Algorithm: " + digestAlgo);
        }
        return digestAlgo;
    }

    public static String getSPEntityID(Map<String, String> properties) {

        String spEntityID = null;
        if (properties != null) {
            spEntityID = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);
            if (log.isDebugEnabled()) {
                log.debug("SP Entity ID: " + spEntityID);
            }
        }
        return spEntityID;
    }

    public static Map<String, String> getQueryMap(String query) {

        Map<String, String> map = new HashMap<>();
        if (StringUtils.isNotBlank(query)) {
            String[] params = query.split("&");
            for (String param : params) {
                String[] paramSplitArr = param.split("=");
                String name = paramSplitArr[0];
                String value = "";
                if (paramSplitArr.length > 1) {
                    value = paramSplitArr[1];
                }
                map.put(name, value);
            }
        }
        return map;
    }

    /**
     * Return whether SAML Assertion has the canonicalization method
     * set to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'.
     *
     * @param document
     * @return true if canonicalization method equals to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
     */
    private static boolean isSignedWithComments(Document document) {

        XPath xPath = XPathFactory.newInstance().newXPath();
        try {
            String assertionId = (String) xPath.compile("//*[local-name()='Assertion']/@ID")
                    .evaluate(document, XPathConstants.STRING);

            if (StringUtils.isBlank(assertionId)) {
                return false;
            }

            NodeList nodeList = ((NodeList) xPath.compile(
                    "//*[local-name()='Assertion']" +
                            "/*[local-name()='Signature']" +
                            "/*[local-name()='SignedInfo']" +
                            "/*[local-name()='Reference'][@URI='#" + assertionId + "']" +
                            "/*[local-name()='Transforms']" +
                            "/*[local-name()='Transform']" +
                            "[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#WithComments']")
                    .evaluate(document, XPathConstants.NODESET));
            return nodeList != null && nodeList.getLength() > 0;
        } catch (XPathExpressionException e) {
            String message = "Failed to find the canonicalization algorithm of the assertion. Defaulting to: " +
                    "http://www.w3.org/2001/10/xml-exc-c14n#";
            log.warn(message);
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            return false;
        }
    }

    private static Document getDocument(DocumentBuilderFactory documentBuilderFactory, String samlString)
            throws IOException, SAXException, ParserConfigurationException {

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(samlString.getBytes());
        return docBuilder.parse(inputStream);
    }

    /**
     * Load a keystore from a given path.
     *
     * @param keyStorePath Path to the keystore file.
     * @param password     Password of the keystore.
     * @param type         Type of the keystore.
     * @return
     */
    public static KeyStore loadKeyStoreFromFileSystem(String keyStorePath, String password, String type) {

        try (FileInputStream inputStream = new FileInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            return keyStore;
        } catch (KeyStoreException e1) {
            throw new java.lang.SecurityException("Could not get a keystore instance of type: " + type + ": " + e1);
        } catch (IOException e2) {
            throw new java.lang.SecurityException("Could not open keystore in path: " + keyStorePath + ": " + e2);
        } catch (CertificateException | NoSuchAlgorithmException e3) {
            throw new java.lang.SecurityException("Error in loading keystore in path: " + keyStorePath + ": " + e3);
        }
    }
}
