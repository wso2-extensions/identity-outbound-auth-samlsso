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
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.RequestData;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import static org.opensaml.saml.saml2.core.StatusCode.SUCCESS;

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

    public static LogoutRequest buildLogoutRequest(RequestData requestData) {

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

    public static LogoutResponse buildLogoutResponse(RequestData requestData, String statusCode, String statusMsg, String inResponseTo){
        LogoutResponse logoutResp = new LogoutResponseBuilder().buildObject();
        logoutResp.setID(createID());

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(requestData.getSpEntityId());
        logoutResp.setIssuer(issuer);

        logoutResp.setInResponseTo(inResponseTo);
        logoutResp.setVersion(SAMLVersion.VERSION_20);
        logoutResp.setStatus(buildStatus(statusCode, statusMsg));
        logoutResp.setIssueInstant(new DateTime());
        logoutResp.setDestination(requestData.getAcsUrl());
        return logoutResp;
    }


    private static Status buildStatus(String responseStatusCode, String responseStatusMsg) {

        Status status = new StatusBuilder().buildObject();

        // Set the status code.
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(responseStatusCode);
        status.setStatusCode(statusCode);

        // Set the status Message.
        if (StringUtils.isNotBlank(responseStatusMsg)) {
            StatusMessage statusMessage = new StatusMessageBuilder().buildObject();
            statusMessage.setMessage(responseStatusMsg);
            status.setStatusMessage(statusMessage);
        }
        return status;
    }

    private static String encode(XMLObject message, String binding) throws
            MarshallingException, IOException{
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(message);
        Element authDOM;
        authDOM = marshaller.marshall(message);
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
            return new String(org.apache.commons.codec.binary.Base64.encodeBase64(byteArrayOutputStream.toByteArray(), false));
        } else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
            return new String(org.apache.commons.codec.binary.Base64.encodeBase64(rspWrt.toString().getBytes(), false));
        } else {
            return new String(org.apache.commons.codec.binary.Base64.encodeBase64(rspWrt.toString().getBytes(), false));
        }
    }
    private static String encodeRequestMessage(RequestAbstractType requestMessage, String binding) throws
            MarshallingException, IOException {

        return encode(requestMessage,binding);
    }

    public static String encodeResponseMessage(LogoutResponse responseMessage, String binding) throws
            MarshallingException, IOException {

        return encode(responseMessage,binding);
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
}
