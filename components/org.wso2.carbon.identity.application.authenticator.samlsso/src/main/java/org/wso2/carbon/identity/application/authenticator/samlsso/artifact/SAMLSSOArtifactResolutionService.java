/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.artifact;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.opensaml.xml.Configuration.getMarshallerFactory;

public class SAMLSSOArtifactResolutionService {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolutionService.class);

    private AuthenticatorConfig authenticatorConfig;
    private ServerConfiguration serverConfig;
    // end url to send soap request
    private String artifactResolveUrl;
    // issuer that needs to be added to the soap request
    private String artifactResolveIssuer;
    // signature algorithm to sign the artifact resolve request
    private String signatureAlgo;
    private String digestAlgo;

    public SAMLSSOArtifactResolutionService(Map<String, String> authenticatorProperties) {
        this.authenticatorConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                .get(SSOConstants.AUTHENTICATOR_NAME);
        this.serverConfig = ServerConfiguration.getInstance();
        artifactResolveUrl = authenticatorProperties.get(SSOConstants.ServerConfig.ARTIFACT_RESOLVE_URL);
        artifactResolveIssuer = authenticatorProperties.get(SSOConstants.ServerConfig.ARTIFACT_RESOLVE_ISSUER);
        signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms()
                .get(getSignatureAlgoProperty(authenticatorProperties));
        digestAlgo = IdentityApplicationManagementUtil.getXMLDigestAlgorithms()
                .get(getDigestAlogProperty(authenticatorProperties));
    }

    /**
     * Create a SAML artifactResolveObject based on given samlArt parameter.
     * This SAML ArtifactResolveObject is wrapped into a soapRequest.
     * A two sided SSL connection is created and the soapRequest is send to an Artifact Resolve Endpoint.
     *
     * @param samlArt SAML Artifact reference needed to get the actual data
     * @return ArtifactResponse
     */
    public String getSAMLArtifactResolveResponse(String samlArt) throws ArtifactResolutionException {

        validateArtifactResolveConfig();
        SSLSocketFactory sslSocketFactory = createSSLSocketFactory(serverConfig);
        SAMLSSOSoapMessageService soapMessageService = new SAMLSSOSoapMessageService(sslSocketFactory);
        ArtifactResolve artifactResolve = createArtifactResolveObject(samlArt, artifactResolveIssuer);
        Envelope envelope = soapMessageService.buildSOAPMessage(artifactResolve);
        Element envelopeElement = marshallMessage(envelope);

        if (log.isDebugEnabled()) {
            log.debug("Writing SOAP Message:\n" + XMLHelper.prettyPrintXML(envelopeElement));
        }

        Proxy proxy = getArtifactResolveProxy();
        //send the soap message
        String soapResponse = soapMessageService.sendSOAP(XMLHelper.nodeToString(envelopeElement), artifactResolveUrl, proxy);
        Pattern p = Pattern.compile("<samlp:ArtifactResponse.+</samlp:ArtifactResponse>", Pattern.DOTALL);
        Matcher m = p.matcher(soapResponse);

        if (m.find()) {
            return m.group(0);
        } else {
            throw new ArtifactResolutionException("No valid SoapResponse");
        }
    }

    private Proxy getArtifactResolveProxy() {
        Proxy proxy = null;
        if (authenticatorConfig != null) {

            if (StringUtils.isNotBlank(authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.ARTIFACT_RESOLVE_PROXY_HOST))) {
                String proxyHost = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.ARTIFACT_RESOLVE_PROXY_HOST);
                String proxyPort = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.ARTIFACT_RESOLVE_PROXY_PORT);
                InetSocketAddress proxyInet = new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort));
                proxy = new Proxy(Proxy.Type.HTTP, proxyInet);
            }
        }
        return proxy;
    }

    private void validateArtifactResolveConfig() throws ArtifactResolutionException {
        if (StringUtils.isEmpty(artifactResolveUrl)) {
            throw new ArtifactResolutionException("Mandatory property artifactResolveUrl is empty");
        }
        if (StringUtils.isEmpty(artifactResolveIssuer)) {
            throw new ArtifactResolutionException("Mandatory property artifactResolveIssuer is empty");
        }
    }

    /**
     * Create SAML ArtifactResolve Object and sign
     *
     * @param sReceivedArtifact object reference to actual data
     * @param artifactResolveIssuer name of issuer that needs to be added to ArtifactResolveObject
     * @return SAML ArtifactResolve Object
     */
    private ArtifactResolve createArtifactResolveObject(String sReceivedArtifact, String artifactResolveIssuer)
            throws ArtifactResolutionException {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) builderFactory.getBuilder
                (Artifact.DEFAULT_ELEMENT_NAME);
        Artifact artifact = artifactBuilder.buildObject();
        artifact.setArtifact(sReceivedArtifact);

        SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder = (SAMLObjectBuilder<ArtifactResolve>)
                builderFactory.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
        ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
        artifactResolve.setVersion(SAMLVersion.VERSION_20);
        artifactResolve.setID(UUID.randomUUID().toString());
        artifactResolve.setIssueInstant(new DateTime());

        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder
                (Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(artifactResolveIssuer);
        artifactResolve.setIssuer(issuer);
        artifactResolve.setArtifact(artifact);

        return (ArtifactResolve) signSamlObject(serverConfig, artifactResolve);
    }

    /**
     * Sign SAML object
     *
     * @param serverConfig serverConfig Object contains keystore properties as defined in carbon.xml
     * @param obj Object that needs to be signed
     */
    private SignableSAMLObject signSamlObject(ServerConfiguration serverConfig, SignableSAMLObject obj)
            throws ArtifactResolutionException {

        String keyfile = "";
        String keyfilePw = "";
        String keyfileType = "";
        String keyAlias = "";

        if (serverConfig != null) {
            keyfile = serverConfig.getFirstProperty(SSOConstants.ServerConfig.SECURITY_KEYSTORE_LOCATION);
            keyfilePw = serverConfig.getFirstProperty(SSOConstants.ServerConfig.KEY_PASSWORD);
            keyfileType = serverConfig.getFirstProperty(SSOConstants.ServerConfig.SECURITY_KEYSTORE_TYPE);
            keyAlias = serverConfig.getFirstProperty(SSOConstants.ServerConfig.KEY_ALIAS);
        }

        if (!obj.isSigned()) {

            Signature signature = new SignatureBuilder().buildObject();
            //read properties from carbon.xml
            KeyStore ks = loadKeystoreFromResource(keyfile, keyfilePw, keyfileType);
            PrivateKey privKey = null;
            String certificate = null;
            try {
                privKey = (PrivateKey) ks.getKey(keyAlias, keyfilePw.toCharArray());
                certificate = org.apache.xml.security.utils.Base64.encode(ks.getCertificate(keyAlias).getEncoded());
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new ArtifactResolutionException("Error when getting the private key for signing", e);
            } catch (CertificateEncodingException e) {
                throw new ArtifactResolutionException("Error when getting the certificate for signing", e);
            }

            BasicCredential credential = new BasicCredential();
            credential.setPrivateKey(privKey);
            signature.setSigningCredential(credential);
            signature.setSignatureAlgorithm(signatureAlgo);
            signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
            X509Certificate x509Certificate = new X509CertificateBuilder().buildObject();
            x509Certificate.setValue(certificate);

            X509Data data = new X509DataBuilder().buildObject();
            data.getX509Certificates().add(x509Certificate);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);

            obj.setSignature(signature);

            SAMLObjectContentReference contentReference = new SAMLObjectContentReference(obj);
            contentReference.setDigestAlgorithm(digestAlgo);
            signature.getContentReferences().clear();
            signature.getContentReferences().add(contentReference);

            try {
                getMarshallerFactory().getMarshaller(obj).marshall(obj);
            } catch (MarshallingException e) {
                throw new ArtifactResolutionException("Error when marshalling for signature", e);
            }
            try {
                Signer.signObject(signature);
            } catch (SignatureException e) {
                throw new ArtifactResolutionException("Error in signing the SAML request", e);
            }
        } else {
            log.info("Object is already signed!");
        }

        return obj;
    }

    /**
     * @param serverConfig serverConfig Object that contains properties that are configured in carbon.xml
     * @return sslsocketfactory or null if creation failed
     * @throws GeneralSecurityException
     * @throws IOException
     */
    private SSLSocketFactory createSSLSocketFactory(final ServerConfiguration serverConfig)
            throws ArtifactResolutionException {
        SSLSocketFactory factory = null;
        SSLContext ctx;
        KeyManagerFactory kmf;
        KeyStore ks;

        String keyfile = "";
        String keyfilePw = "";
        String keyfileType = "";

        if (serverConfig != null) {
            keyfile = serverConfig.getFirstProperty(SSOConstants.ServerConfig.SECURITY_KEYSTORE_LOCATION);
            keyfilePw = serverConfig.getFirstProperty(SSOConstants.ServerConfig.KEY_PASSWORD);
            keyfileType = serverConfig.getFirstProperty(SSOConstants.ServerConfig.SECURITY_KEYSTORE_TYPE);
        }

        char[] kspassphrase = keyfilePw.toCharArray();

        try {
            ctx = SSLContext.getInstance("TLS");
            kmf = KeyManagerFactory.getInstance("SunX509");
            ks = loadKeystoreFromResource(keyfile, keyfilePw, keyfileType);
            kmf.init(ks, kspassphrase);
            ctx.init(kmf.getKeyManagers(), null, null);
            factory = ctx.getSocketFactory();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
            throw new ArtifactResolutionException("Error when generating the SSL Socket Factory", e);
        }
        return factory;

    }

    private KeyStore loadKeystoreFromResource(String resource, String password, String type)
            throws ArtifactResolutionException {
        try (InputStream is = Files.newInputStream(Paths.get(resource))) {
            KeyStore keystore = KeyStore.getInstance(type);
            keystore.load(is, password.toCharArray());
            return keystore;
        } catch (KeyStoreException | NoSuchAlgorithmException | IOException | CertificateException e) {
            throw new ArtifactResolutionException("Error when loading keystore from resource.", e);
        }
    }

    /**
     * Helper method that marshall the given message
     *
     * @param message message to get marshalled and serialized
     * @return marshalled message
     * @throws MessageEncodingException, if the give message can not be marshalled into its DOM representation
     */
    private Element marshallMessage(XMLObject message) throws ArtifactResolutionException {

        try {
            Marshaller marshaller = getMarshallerFactory().getMarshaller(message);
            if (marshaller == null) {
                throw new ArtifactResolutionException("Unable to marshall message, no marshaller registered for " +
                        "message object: " + message.getElementQName());
            }
            Element messageElem = marshaller.marshall(message);
            return messageElem;
        } catch (MarshallingException e) {
            throw new ArtifactResolutionException("Encountered error marshalling message into its DOM representation", e);
        }
    }

    private String getSignatureAlgoProperty(Map<String, String> authenticatorProperties) {
        // get Signature Algorithm
        String signatureAlgoProp = authenticatorProperties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(signatureAlgoProp)) {
            signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
        }
        return signatureAlgoProp;
    }

    private String getDigestAlogProperty(Map<String, String> authenticatorProperties) {
        // get Digest Algorithm
        String digestAlgoProp = authenticatorProperties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        if (StringUtils.isEmpty(digestAlgoProp)) {
            digestAlgoProp = IdentityApplicationConstants.XML.DigestAlgorithm.SHA1;
        }
        return digestAlgoProp;
    }
}
