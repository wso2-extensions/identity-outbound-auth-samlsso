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
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusCode;
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

/**
 * This class is used for handling SAML Artifact Binding
 */
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
     * @param samlArtReceived SAML Artifact reference needed to get the actual data
     * @return ArtifactResponse
     */
    public ArtifactResponse getSAMLArtifactResponse(String samlArtReceived) throws ArtifactResolutionException {

        validateArtifactResolveConfig();
        ArtifactResolve artifactResolve = generateArtifactResolveReq(samlArtReceived);
        return sendArtifactResolveRequest(artifactResolve);
    }

    /**
     * Create SAML ArtifactResolve Object and sign
     *
     * @param samlArtReceived object reference to actual data
     * @return SAML ArtifactResolve Object
     */
    public ArtifactResolve generateArtifactResolveReq(String samlArtReceived) throws ArtifactResolutionException {

        ArtifactResolve artifactResolve = createArtifactResolveObject(samlArtReceived);
        if (SSOUtils.isArtifactResolveReqSigningEnabled(authenticatorProperties)) {
            if (log.isDebugEnabled()) {
                log.debug("Signing artifact resolve request for the received SAML artifact : " + samlArtReceived);
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
    public ArtifactResponse sendArtifactResolveRequest(ArtifactResolve artifactResolve) throws ArtifactResolutionException {

        SAMLSSOSoapMessageService soapMessageService = new SAMLSSOSoapMessageService();
        Envelope envelope = soapMessageService.buildSOAPMessage(artifactResolve);
        String envelopeElement;
        try {
            envelopeElement = SSOUtils.marshall(envelope);
        } catch (SAMLSSOException e) {
            throw new ArtifactResolutionException("Encountered error marshalling SOAP message with artifact resolve, " +
                    "into its DOM representation", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Artifact Resolve Request as a SOAP Message: " + envelopeElement);
        }

        String artifactResponseString = soapMessageService.sendSOAP(envelopeElement, SSOUtils.getArtifactResolveUrl
                (authenticatorProperties));
        Pattern pattern = Pattern.compile("<samlp:ArtifactResponse.+</samlp:ArtifactResponse>", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(artifactResponseString);
        if (matcher.find()) {
            String artifactResponseReceived = matcher.group(0);
            if (log.isDebugEnabled()) {
                log.debug("Artifact Response: " + artifactResponseReceived);
            }
            try {
                ArtifactResponse artifactResponse = (ArtifactResponse) SSOUtils.unmarshall(artifactResponseReceived);
                if (isArtifactResponseValid(artifactResolve, artifactResponse)) {
                    return artifactResponse;
                } else {
                    throw new ArtifactResolutionException("Artifact Response is not valid.");
                }
            } catch (SAMLSSOException e) {
                throw new ArtifactResolutionException("Encountered error unmarshalling response into SAML2 object", e);
            }
        } else {
            throw new ArtifactResolutionException("Didn't receive valid artifact response.");
        }
    }

    private boolean isArtifactResponseValid(ArtifactResolve artifactResolve, ArtifactResponse artifactResponse)
            throws ArtifactResolutionException {

        if (artifactResponse == null) {
            throw new ArtifactResolutionException("Did not receive an artifact response message.");
        }

        String artifactResolveId = artifactResolve.getID();
        String artifactResponseInResponseTo = artifactResponse.getInResponseTo();
        if (!artifactResolveId.equals(artifactResponseInResponseTo)) {
            throw new ArtifactResolutionException("Artifact resolve ID: " + artifactResolveId + " is not equal to " +
                    "artifact response InResponseTo : " + artifactResponseInResponseTo);
        }

        String artifactResponseStatus = artifactResponse.getStatus().getStatusCode().getValue();
        if (!StatusCode.SUCCESS_URI.equals(artifactResponseStatus)) {
            throw new ArtifactResolutionException("Unsuccessful artifact response with status: " +
                    artifactResponseStatus);
        }

        SAMLObject message = artifactResponse.getMessage();
        if (message == null) {
            throw new ArtifactResolutionException("No SAML response embedded into the artifact response.");
        }

        return true;
    }

    private void validateArtifactResolveConfig() throws ArtifactResolutionException {

        if (StringUtils.isEmpty(SSOUtils.getArtifactResolveUrl(authenticatorProperties))) {
            throw new ArtifactResolutionException("Artifact Resolve Url is not configured.");
        }
        if (StringUtils.isEmpty(SSOUtils.getSPEntityID(authenticatorProperties))) {
            throw new ArtifactResolutionException("Artifact Resolve Issuer is not configured.");
        }
    }

    private ArtifactResolve createArtifactResolveObject(String samlArtReceived) {

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
        artifact.setArtifact(samlArtReceived);

        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(SSOUtils.getSPEntityID(authenticatorProperties));

        artifactResolve.setIssuer(issuer);
        artifactResolve.setArtifact(artifact);

        return artifactResolve;
    }

    private void signArtifactResolveReq(RequestAbstractType artifactResolveObj) throws ArtifactResolutionException {

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
