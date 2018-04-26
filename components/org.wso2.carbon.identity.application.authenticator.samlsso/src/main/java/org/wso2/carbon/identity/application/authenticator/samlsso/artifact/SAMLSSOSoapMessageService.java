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
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.opensaml.common.SAMLObject;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.UnknownHostException;

public class SAMLSSOSoapMessageService {
    private static Log log = LogFactory.getLog(SAMLSSOSoapMessageService.class);
    private static final String CONTENT_TYPE = "text/xml; charset=utf-8";

    /**
     * Build a SOAP Message.
     *
     * @param samlMessage SAMLObject.
     * @return Envelope soap envelope
     */
    public Envelope buildSOAPMessage(SAMLObject samlMessage) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(
                Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envBuilder.buildObject();

        log.info("Adding SAML message to the SOAP message's body");
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
     * @param sMessage message that needs to be send
     * @param sUrl url that the artifact resolve request should be sent
     * @return response of invoking artifact resolve endpoint
     * @throws ArtifactResolutionException
     */
    public String sendSOAP(String sMessage, String sUrl) throws ArtifactResolutionException {

        StringBuilder soapResponse = new StringBuilder();
        try {
            HttpPost httpPost = new HttpPost(sUrl);
            setRequestProperties(sUrl, sMessage, httpPost);
            DefaultHttpClient httpClient = new DefaultHttpClient();
            HttpResponse httpResponse = httpClient.execute(httpPost);

            int responseCode = httpResponse.getStatusLine().getStatusCode();
            if (responseCode != 200) {
                throw new ArtifactResolutionException("Problem in communicating with: " + sUrl + ". Received response: "
                        + responseCode);
            } else {
                log.info("Successful response from the URL: " + sUrl);
                soapResponse.append(stream2string(httpResponse.getEntity().getContent()));
            }
        }
        catch (UnknownHostException eUH) {
            throw new ArtifactResolutionException("Unknown targeted host: " + sUrl , eUH);
        }
        catch (IOException eIO) {
            throw new ArtifactResolutionException("Could not open connection with host: " + sUrl, eIO);
        }
        return soapResponse.toString();
    }

    private void setRequestProperties(String sUrl, String sMessage, HttpPost httpPost) {
        httpPost.addHeader(SSOConstants.CONTENT_TYPE_PARAM_KEY, CONTENT_TYPE);
        httpPost.addHeader(SSOConstants.ACCEPT_PARAM_KEY, CONTENT_TYPE);
        StringBuilder sbSOAPAction = new StringBuilder("\"");
        sbSOAPAction.append(sUrl).append("\"");
        httpPost.addHeader(SSOConstants.SOAP_ACTION_PARAM_KEY, sbSOAPAction.toString());
        httpPost.addHeader(SSOConstants.PRAGMA_PARAM_KEY, "no-cache");
        httpPost.addHeader(SSOConstants.CACHE_CONTROL_PARAM_KEY, "no-cache, no-store");

        httpPost.setEntity(new StringEntity(sMessage, ContentType.create(CONTENT_TYPE)));
    }

    /**
     * Read bytes from input stream till empty and convert to string based on supplied charset encoding.
     *
     * @param is The inputstream to read from.
     * @param enc The character encoding to use in conversion.
     * @return String containing the data from the inputstream
     * @throws IOException Signals that an I/O exception has occurred
     *
     */
    private static String stream2string(InputStream is, String enc)
            throws IOException {

        int xRead;
        byte[] ba = new byte[512];
        DataInputStream isInput = new DataInputStream(new BufferedInputStream(is));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        // Retrieve message as bytes and put them in a string
        while ((xRead = isInput.read(ba)) != -1) {
            bos.write(ba, 0, xRead);
        }
        return bos.toString(enc);
    }

    private static String stream2string(InputStream is)
            throws IOException {

        return stream2string(is, "UTF-8");
    }

}
