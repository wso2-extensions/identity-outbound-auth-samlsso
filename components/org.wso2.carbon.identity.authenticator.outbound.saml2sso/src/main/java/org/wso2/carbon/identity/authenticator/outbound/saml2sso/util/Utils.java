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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.util;

import org.apache.commons.lang.StringUtils;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.Configuration;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SigningUtil;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorException;
import org.wso2.carbon.identity.authenticator.outbound.saml2sso.exception.SAML2SSOAuthenticatorRuntimeException;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class Utils {

    private static final String SECURITY_MANAGER_PROPERTY = Constants.XERCES_PROPERTY_PREFIX +
            Constants.SECURITY_MANAGER_PROPERTY;
    private static final int ENTITY_EXPANSION_LIMIT = 0;

    private Utils() {

    }

    private static Logger log = LoggerFactory.getLogger(Utils.class);

    /**
     * Generates a unique Id for Authentication Requests.
     *
     * @return generated unique ID
     */
    public static String createID() {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new SAML2SSOAuthenticatorRuntimeException("Error while building Secure Random ID", e);
        }
    }

    public static void setSignature(RequestAbstractType request, String signatureAlgorithm,
                                    String digestAlgorithm, boolean includeCert, X509Credential x509Credential)
            throws SAML2SSOAuthenticatorException {

        if (request == null) {
            throw new IllegalArgumentException("Request cannot be null.");
        }
        if (StringUtils.isBlank(signatureAlgorithm)) {
            throw new IllegalArgumentException("Signature algorithm cannot be blank.");
        }
        if (x509Credential == null) {
            throw new IllegalArgumentException("X509Credential cannot be null.");
        }
        if (x509Credential.getEntityCertificate() == null) {
            throw new SAML2SSOAuthenticatorException("Entity Certificate cannot be null.");
        }
        if (x509Credential.getPrivateKey() == null) {
            throw new SAML2SSOAuthenticatorException("Private Key cannot be null.");
        }

        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(x509Credential);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        if (includeCert) {
            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate)
                    buildXMLObject(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
            String value = null;
            try {
                value = Base64.encodeBytes(x509Credential.getEntityCertificate().getEncoded());
            } catch (CertificateEncodingException e) {
                throw new SAML2SSOAuthenticatorException("Error while encoding the certificate to include in the " +
                        "signature", e);
            }
            cert.setValue(value);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);
        }

        request.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0))
                .setDigestAlgorithm(digestAlgorithm);

        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);

        MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
        try {
            marshaller.marshall(request);
        } catch (MarshallingException e) {
            throw new SAML2SSOAuthenticatorException("Error while marshalling the SAML2 message for signing", e);
        }

        try {
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            throw new SAML2SSOAuthenticatorException("Error while signing the SAML2 message", e);
        }
    }

    public static void addSignatureToHTTPQueryString(StringBuilder httpQueryString, String signatureAlgorithmURI,
                                                     X509Credential x509Credential) throws SAML2SSOAuthenticatorException {

        if (httpQueryString != null) {
            throw new IllegalArgumentException("Request cannot be null.");
        }
        if (x509Credential == null) {
            throw new IllegalArgumentException("X509Credential cannot be null.");
        }
        if (x509Credential.getEntityCertificate() == null) {
            throw new SAML2SSOAuthenticatorException("Entity Certificate cannot be null.");
        }
        if (x509Credential.getPrivateKey() == null) {
            throw new SAML2SSOAuthenticatorException("Private Key cannot be null.");
        }

        try {
            if (httpQueryString.charAt(httpQueryString.length() - 1) != '&') {
                httpQueryString.append('&');
            }
            httpQueryString.append("SigAlg=");
            httpQueryString.append(URLEncoder.encode(signatureAlgorithmURI, StandardCharsets.UTF_8.name()).trim());

            byte[] rawSignature = SigningUtil.signWithURI(x509Credential, signatureAlgorithmURI,
                    httpQueryString.toString().getBytes(StandardCharsets.UTF_8.name()));

            String base64Signature = Base64.encodeBytes(rawSignature, Base64.DONT_BREAK_LINES);

            if (log.isDebugEnabled()) {
                log.debug("Generated digital signature base64 encoded value " + base64Signature);
            }

            httpQueryString.append("&Signature=" + URLEncoder.encode(base64Signature, StandardCharsets.UTF_8.name())
                    .trim());

        } catch (org.opensaml.xml.security.SecurityException e) {
            throw new SAML2SSOAuthenticatorException("Unable to sign query string", e);
        } catch (UnsupportedEncodingException e) {
            throw new SAML2SSOAuthenticatorException("Unsupported encoding algorithm. UTF-8 encoding is required to " +
                    "be supported by all JVMs", e);
        }
    }

    public static XMLObject buildXMLObject(QName objectQName) throws SAML2SSOAuthenticatorException {

        XMLObjectBuilder builder = org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            throw new SAML2SSOAuthenticatorException("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }

    public static String encodeForRedirect(RequestAbstractType requestMessage)
            throws SAML2SSOAuthenticatorException {

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        try {
            authDOM = marshaller.marshall(requestMessage);

            /* Compress the message */
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            deflaterOutputStream.write(rspWrt.toString().getBytes());
            deflaterOutputStream.close();

            /* Encoding the compressed message */
            String encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream
                    .toByteArray(), Base64.DONT_BREAK_LINES);

            byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.toString();

            // log saml
            if (log.isDebugEnabled()) {
                log.debug("SAML Request  :  " + rspWrt.toString());
            }

            return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();

        } catch (MarshallingException e) {
            throw new SAML2SSOAuthenticatorException("Error occurred while encoding SAML request", e);
        } catch (UnsupportedEncodingException e) {
            throw new SAML2SSOAuthenticatorException("Error occurred while encoding SAML request", e);
        } catch (IOException e) {
            throw new SAML2SSOAuthenticatorException("Error occurred while encoding SAML request", e);
        }
    }

    public static String encodeForPost(String xmlString) {
        String encodedRequestMessage = Base64.encodeBytes(xmlString.getBytes(), Base64.DONT_BREAK_LINES);
        return encodedRequestMessage.trim();
    }

    public static String decodeForRedirect(String encodedStr) throws SAML2SSOAuthenticatorException {
        try {
            if (log.isDebugEnabled()) {
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

                if (!inflater.finished()) {
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
            throw new SAML2SSOAuthenticatorException("Error when decoding the SAML Request.", e);
        }

    }

    public static String decodeForPost(String encodedStr) throws SAML2SSOAuthenticatorException {

        try {
            byte[] base64DecodedByteArray = Base64.decode(encodedStr);
            String decodedString = new String(base64DecodedByteArray, StandardCharsets.UTF_8.name());
            if (log.isDebugEnabled()) {
                log.debug("SAML2 message " + decodedString);
            }
            return decodedString;

        } catch (IOException e) {
            throw new SAML2SSOAuthenticatorException("Error while decoding the SAML2 message.", e);
        }
    }

    public static String marshall(XMLObject xmlObject) throws SAML2SSOAuthenticatorException {
        try {

            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
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
            throw new SAML2SSOAuthenticatorException("Error marshalling the XML object", e);
        }
    }

    public static XMLObject unmarshall(String samlString) throws SAML2SSOAuthenticatorException {

        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilderFactory.setExpandEntityReferences(false);
            documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            org.apache.xerces.util.SecurityManager securityManager = new SecurityManager();
            securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
            documentBuilderFactory.setAttribute(SECURITY_MANAGER_PROPERTY, securityManager);

            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            docBuilder.setEntityResolver(new CarbonEntityResolver());
            ByteArrayInputStream is = new ByteArrayInputStream(samlString.getBytes());
            Document document = docBuilder.parse(is);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (ParserConfigurationException e) {
            throw new SAML2SSOAuthenticatorException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (UnmarshallingException e) {
            throw new SAML2SSOAuthenticatorException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (SAXException e) {
            throw new SAML2SSOAuthenticatorException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (IOException e) {
            throw new SAML2SSOAuthenticatorException("Error in unmarshalling SAML Request from the encoded String", e);
        }

    }

    public static X509Credential getServerCredentials() {
        // reuse Hasintha's code
        return null;
    }

    public static String getAcsUrl() {
        return null;
    }
}
