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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * This class is used for handling SAML SOAP Binding
 */
public class SAMLSSOSoapMessageService {
    private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
    private static final Log log = LogFactory.getLog(SAMLSSOSoapMessageService.class);

    /**
     * Build a SOAP Message.
     *
     * @param samlMessage SAMLObject.
     * @return Envelope soap envelope
     */
    public Envelope buildSOAPMessage(SAMLObject samlMessage) {

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(
                Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envBuilder.buildObject();

        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory.getBuilder(
                Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlMessage);
        envelope.setBody(body);
        return envelope;
    }

    /**
     * Send SOAP message
     *
     * @param message message that needs to be send
     * @param url     url that the artifact resolve request should be sent
     * @param proxy   HttpHost proxy if configured in carbon.xml
     * @return response of invoking artifact resolve endpoint
     * @throws ArtifactResolutionException
     */
    public String sendSOAP(String message, String url, HttpHost proxy) throws ArtifactResolutionException {

        StringBuilder soapResponse = new StringBuilder();
        try {
            HttpPost httpPost = new HttpPost(url);
            setRequestProperties(url, message, httpPost);

            HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
            SSLContext sslContext = getSSLContext(CarbonUtils.getServerConfiguration());

            if (sslContext != null) {
                httpClientBuilder.setSslcontext(sslContext);

                if (proxy != null) {
                    httpClientBuilder.setProxy(proxy);
                }
            }

            CloseableHttpClient httpClient = httpClientBuilder.build();
            HttpResponse httpResponse = httpClient.execute(httpPost);

            int responseCode = httpResponse.getStatusLine().getStatusCode();
            if (responseCode != 200) {
                throw new ArtifactResolutionException("Problem in communicating with: " + url + ". Received response: "
                        + responseCode);
            } else {
                log.info("Successful response from the URL: " + url);
                soapResponse.append(getResponseBody(httpResponse));
            }
        } catch (UnknownHostException e1) {
            throw new ArtifactResolutionException("Unknown targeted host: " + url, e1);
        } catch (IOException e2) {
            throw new ArtifactResolutionException("Could not open connection with host: " + url, e2);
        } catch (GeneralSecurityException e3) {
            throw new ArtifactResolutionException("Error in creating SSL context: " + e3);
        }
        return soapResponse.toString();
    }

    /**
     * Create an SSLContext object by parsing the Keystore configured in carbon.xml file.
     *
     * @param serverConfig serverConfig Object that contains properties configured in carbon.xml.
     * @return SSLContext or null if creation failed.
     * @throws GeneralSecurityException
     */
    private SSLContext getSSLContext(final ServerConfiguration serverConfig)
            throws GeneralSecurityException {

        SSLContext sslContext = null;
        KeyManagerFactory keyManagerFactory;
        KeyStore keyStore;
        String keyStorePath;
        String keyStorePassword;
        String keyStoreType;

        if (serverConfig != null) {
            keyStorePath = serverConfig.getFirstProperty(SSOConstants.SECURITY_KEYSTORE_LOCATION);
            keyStorePassword = serverConfig.getFirstProperty(SSOConstants.ServerConfig.KEY_PASSWORD);
            keyStoreType = serverConfig.getFirstProperty(SSOConstants.SECURITY_KEYSTORE_TYPE);

            char[] kspassphrase = keyStorePassword.toCharArray();

            sslContext = SSLContext.getInstance("TLSv1.2");
            keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyStore = SSOUtils.loadKeyStoreFromFileSystem(keyStorePath, keyStorePassword, keyStoreType);
            keyManagerFactory.init(keyStore, kspassphrase);
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            if (log.isDebugEnabled()) {
                log.debug("Created SSL Context using keystore: " + keyStorePath + " and keyStorePassword: " +
                        keyStorePassword);
            }
        }

        return sslContext;
    }

    private void setRequestProperties(String url, String message, HttpPost httpPost) {

        httpPost.addHeader(SSOConstants.CONTENT_TYPE_PARAM_KEY, CONTENT_TYPE);
        httpPost.addHeader(SSOConstants.ACCEPT_PARAM_KEY, CONTENT_TYPE);
        String sbSOAPAction = "\"" + url + "\"";
        httpPost.addHeader(SSOConstants.SOAP_ACTION_PARAM_KEY, sbSOAPAction);
        httpPost.addHeader(SSOConstants.PRAGMA_PARAM_KEY, "no-cache");
        httpPost.addHeader(SSOConstants.CACHE_CONTROL_PARAM_KEY, "no-cache, no-store");

        httpPost.setEntity(new StringEntity(message, ContentType.create("text/xml", "UTF-8")));
    }

    private static String getResponseBody(HttpResponse response) throws ArtifactResolutionException {

        ResponseHandler<String> responseHandler = new BasicResponseHandler();
        String responseBody;
        try {
            responseBody = responseHandler.handleResponse(response);
        } catch (IOException e) {
            throw new ArtifactResolutionException("Error when retrieving the HTTP response body.", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Response Body:" + responseBody);
        }
        return responseBody;
    }
}
