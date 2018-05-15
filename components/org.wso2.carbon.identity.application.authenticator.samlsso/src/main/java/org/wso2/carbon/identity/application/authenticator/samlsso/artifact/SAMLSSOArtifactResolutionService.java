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
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.X509CredentialImpl;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;

import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SAMLSSOArtifactResolutionService {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolutionService.class);

    private Map<String, String> authenticatorProperties;
    private String tenantDomain;

    public SAMLSSOArtifactResolutionService(Map<String, String> authenticatorProperties, String tenantDomain) {
        this.authenticatorProperties = authenticatorProperties;
        this.tenantDomain = tenantDomain;
    }

    /**
     * Create a SAML artifactResolveObject based on given samlArt parameter and wrapped into a soapRequest
     * Send the soapRequest to the Artifact Resolve Endpoint
     *
     * @param samlArt SAML Artifact reference needed to get the actual data
     * @return ArtifactResponse
     */
    public String getSAMLArtifactResolveResponse(String samlArt) throws ArtifactResolutionException {

        validateArtifactResolveConfig();
        ArtifactResolve artifactResolve = generateArtifactResolveReq(samlArt);
        return sendArtifactResolveRequest(artifactResolve);
    }

    /**
     * Create SAML ArtifactResolve Object and sign
     *
     * @param sReceivedArtifact object reference to actual data
     * @return SAML ArtifactResolve Object
     */
    public ArtifactResolve generateArtifactResolveReq(String sReceivedArtifact) throws ArtifactResolutionException {

        ArtifactResolve artifactResolve = createArtifactResolveObject(sReceivedArtifact);
        if (SSOUtils.isArtifactResolveReqSigned(authenticatorProperties)) {
            if(log.isDebugEnabled()) {
                log.debug("Signing artifact resolve request.");
            }
            signArtifactResolveReq(artifactResolve);
        }
        return artifactResolve;
    }

    /**
     * Send Artifact Resolve Request to Artifact Resolution Service
     *
     * @param artifactResolve Artifact Resolve Request
     * @return ArtifactResponse
     * @throws ArtifactResolutionException
     */
    public String sendArtifactResolveRequest(ArtifactResolve artifactResolve) throws ArtifactResolutionException {

        SAMLSSOSoapMessageService soapMessageService = new SAMLSSOSoapMessageService();
        Envelope envelope = soapMessageService.buildSOAPMessage(artifactResolve);
        String envelopeElement;
        try {
            envelopeElement = SSOUtils.marshall(envelope);
        } catch (SAMLSSOException e) {
            throw new ArtifactResolutionException("Encountered error marshalling message into its DOM representation", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Artifact Resolve Request as a SOAP Message: " + envelopeElement);
        }

        String artifactResponse = soapMessageService.sendSOAP(envelopeElement, SSOUtils.getArtifactResolveUrl
                (authenticatorProperties));
        Pattern p = Pattern.compile("<samlp:ArtifactResponse.+</samlp:ArtifactResponse>", Pattern.DOTALL);
        Matcher m = p.matcher(artifactResponse);

        if (m.find()) {
            if (log.isDebugEnabled()) {
                log.debug("Artifact Response: " + m.group(0));
            }
            return m.group(0);
        } else {
            throw new ArtifactResolutionException("Didn't receive valid artifact response.");
        }
    }

    private void validateArtifactResolveConfig() throws ArtifactResolutionException {

        if (StringUtils.isEmpty(SSOUtils.getArtifactResolveUrl(authenticatorProperties))) {
            throw new ArtifactResolutionException("Artifact Resolve Url is not configured.");
        }
        if (StringUtils.isEmpty(SSOUtils.getSPEntityID(authenticatorProperties))) {
            throw new ArtifactResolutionException("Artifact Resolve Issuer is not configured.");
        }
    }

    private ArtifactResolve createArtifactResolveObject(String sReceivedArtifact) {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder =
                (SAMLObjectBuilder<ArtifactResolve>) builderFactory.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
        ArtifactResolve artifactResolve = artifactResolveBuilder.buildObject();
        artifactResolve.setVersion(SAMLVersion.VERSION_20);
        artifactResolve.setID(UUID.randomUUID().toString());
        artifactResolve.setIssueInstant(new DateTime());

        SAMLObjectBuilder<Artifact> artifactBuilder =
                (SAMLObjectBuilder<Artifact>) builderFactory.getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
        Artifact artifact = artifactBuilder.buildObject();
        artifact.setArtifact(sReceivedArtifact);

        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(SSOUtils.getSPEntityID(authenticatorProperties));

        artifactResolve.setIssuer(issuer);
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

    private void signArtifactResolveReq(RequestAbstractType artifactResolveObj)
            throws ArtifactResolutionException {

        try {
            String signatureAlgo = SSOUtils.getSignatureAlgorithm(authenticatorProperties);
            String digestAlgo = SSOUtils.getDigestAlgorithm(authenticatorProperties);
            SSOUtils.setSignature(artifactResolveObj, signatureAlgo, digestAlgo, true,
                    new X509CredentialImpl(tenantDomain, null));
        } catch (SAMLSSOException e) {
            throw new ArtifactResolutionException("Error in signing the Artifact Resolve request", e);
        }
    }
}
