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

package org.wso2.carbon.identity.application.authenticator.samlsso;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.RequestData;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Test util methods
 */
public class TestUtils {

    private TestUtils() {

    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf", fileName).toString();
        }
        return null;
    }

    public static String buildRequest(boolean isLogout, RequestData requestData) throws IOException, MarshallingException {

        RequestAbstractType requestMessage;
        if (!isLogout) {
            requestMessage = buildAuthnRequest(requestData);
        } else {
            requestMessage = buildLogoutRequest(requestData);
        }

        return encodeRequestMessage(requestMessage, requestData.getHttpBinding());
    }

    private static AuthnRequest buildAuthnRequest(RequestData requestData) {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
        issuer.setValue(requestData.getSpEntityId());

        // NameIDPolicy
        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdPolicy.setSPNameQualifier("Issuer");
        nameIdPolicy.setAllowCreate(true);

        // AuthnContextClass
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject
                ("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef", "saml");
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2" +
                ".0:ac:classes:PasswordProtectedTransport");

        // AuthnContex
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();

        // Creation of AuthRequestObject
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");

        authRequest.setForceAuthn(requestData.isForce());
        authRequest.setIsPassive(requestData.isPassive());
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding(requestData.getHttpBinding());
        authRequest.setAssertionConsumerServiceURL(requestData.getAcsUrl());
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(requestData.getIdPUrl());

        // Requesting Attributes.
        if (StringUtils.isNotBlank(requestData.getAcsIndex())) {
            authRequest.setAttributeConsumingServiceIndex(Integer.parseInt(requestData.getAcsIndex()));
        }

        return authRequest;
    }

    private static LogoutRequest buildLogoutRequest(RequestData requestData) {

        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();

        logoutReq.setID(createID());
        logoutReq.setDestination(requestData.getIdPUrl());
        logoutReq.setReason("Single Logout");

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requestData.getSpEntityId());
        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(requestData.getUser());
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
        sessionIndex.setSessionIndex(requestData.getSessionIndex());
        logoutReq.getSessionIndexes().add(sessionIndex);

        return logoutReq;
    }

    private static String encodeRequestMessage(RequestAbstractType requestMessage, String binding) throws
            MarshallingException, IOException {

        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM;
        authDOM = marshaller.marshall(requestMessage);
        OutputStream rspWrt = new ByteArrayOutputStream();
        SerializeSupport.writeNode(authDOM, rspWrt);
        if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(binding)) {
            //Compress the message, Base 64 encode and URL encode
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream
                    (byteArrayOutputStream, deflater);
            deflaterOutputStream.write(rspWrt.toString().getBytes(Charset.forName("UTF-8")));
            deflaterOutputStream.close();
            return Base64Support.encode(byteArrayOutputStream.toByteArray(), Base64Support.UNCHUNKED);
        } else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
            return Base64Support.encode(rspWrt.toString().getBytes(), Base64Support.UNCHUNKED);
        } else {
            return Base64Support.encode(rspWrt.toString().getBytes(), Base64Support.UNCHUNKED);
        }
    }

    public static XMLObject unmarshall(String authReqStr) throws Exception {

        try (InputStream inputStream = new ByteArrayInputStream(authReqStr.trim().getBytes(StandardCharsets.UTF_8))) {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        }
    }

    private static String createID() {

        byte[] bytes = new byte[20]; // 160 bit

        new Random().nextBytes(bytes);

        char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

        char[] chars = new char[40];

        for (int i = 0; i < bytes.length; i++) {
            int left = (bytes[i] >> 4) & 0x0f;
            int right = bytes[i] & 0x0f;
            chars[i * 2] = charMapping[left];
            chars[i * 2 + 1] = charMapping[right];
        }

        return String.valueOf(chars);
    }

    public static void doBootstrap() {

        /* Initializing the OpenSAML library */

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

        } catch (InitializationException e) {
            e.printStackTrace();
        } finally {
            thread.setContextClassLoader(loader);
        }
    }
}
