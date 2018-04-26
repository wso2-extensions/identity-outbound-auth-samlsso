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
import org.opensaml.common.SAMLObject;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.UnknownHostException;

public class SAMLSSOSoapMessageService {
    private static Log log = LogFactory.getLog(SAMLSSOSoapMessageService.class);
    private static final String CONTENT_TYPE = "text/xml; charset=utf-8";
    private static final String HTTPS = "https";
    private SSLSocketFactory sslSocketFactory = null;

    public SAMLSSOSoapMessageService(SSLSocketFactory socketFactory) {
        sslSocketFactory = socketFactory;
    }

    /**
     * Build a SOAP Message.
     *
     * @param samlMessage SAMLObject.
     * @return Envelope soap envelope
     */
    public Envelope buildSOAPMessage(SAMLObject samlMessage)
    {
        XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

        SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
                .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envBuilder.buildObject();

        log.info("Adding SAML message to the SOAP message's body");
        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
                .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlMessage);
        envelope.setBody(body);
        return envelope;
    }

    /**
     * Send SOAP message.
     *
     * @param sMessage message that needs to be send
     * @param sUrl url that the message should be sent
     * @return the response
     * @throws Exception If sending fails
     */
    public String sendSOAP(String sMessage, String sUrl, Proxy proxy) throws ArtifactResolutionException
    {
        StringBuilder sb = new StringBuilder();
        URL url = null;
        HttpURLConnection connection = null;
        HttpsURLConnection sslConnection = null;

        try {
            url = new URL(sUrl);
            if (sslSocketFactory != null && url.getProtocol().equalsIgnoreCase(HTTPS) ) {
                if (proxy != null) {
                    sslConnection = (HttpsURLConnection) url.openConnection(proxy);
                } else {
                    sslConnection = (HttpsURLConnection) url.openConnection();
                }
                sslConnection.setSSLSocketFactory(sslSocketFactory);
                connection = sslConnection;
            } else {
                connection = (HttpURLConnection) url.openConnection();
            }

            // enable sending to connection
            connection.setDoOutput(true);

            // set mime headers
            connection.setRequestProperty("Content-Type", CONTENT_TYPE);
            connection.setRequestProperty("Accept", CONTENT_TYPE);
            StringBuilder sbSOAPAction = new StringBuilder("\"");
            sbSOAPAction.append(sUrl).append("\"");
            connection.setRequestProperty("SOAPAction", sbSOAPAction.toString());
            log.info("Send: Url=" + sUrl + " ContentType=" + CONTENT_TYPE + " Action=" + sbSOAPAction);

            connection.setRequestProperty("Pragma", "no-cache");
            connection.setRequestProperty("Cache-Control", "no-cache, no-store");
            // write message to output
            PrintStream osOutput = new PrintStream((connection).getOutputStream());
            osOutput.println(sMessage);
            osOutput.println("\r\n\r\n");
            osOutput.close();

            int responseCode = connection.getResponseCode();
            switch (responseCode) {
                case 200: // ok
                    log.info("Response OK: ContentType: " + connection.getContentType());
                    sb = new StringBuilder(stream2string(connection.getInputStream()));
                    break;
                case 500: // Internal server error
                    log.warn("No response from target host. Errorcode: " + responseCode);
                    break;
                default: // unknown error
                    StringBuilder builder = new StringBuilder("Invalid response from target host: \"");
                    builder.append(connection.getHeaderField(0));
                    builder.append(" \". Errorcode: " + responseCode);
                    log.warn(builder.toString());
                    break;
            }
        }
        catch (UnknownHostException eUH) {
            throw new ArtifactResolutionException("Unknown targeted host: " + url.toString() , eUH);
        }
        catch (IOException eIO) {
            throw new ArtifactResolutionException("Could not open connection with host:" + url.toString(), eIO);
        }
        return sb.toString();
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
            throws IOException
    {
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
            throws IOException
    {
        return stream2string(is, "UTF-8");
    }

}
