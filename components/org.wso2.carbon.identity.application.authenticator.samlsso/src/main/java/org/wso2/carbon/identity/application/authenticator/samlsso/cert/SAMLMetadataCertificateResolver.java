/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.samlsso.cert;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.X509Data;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.RemoteCertificate;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;

import static org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOErrorConstants.ErrorMessages.*;
import org.wso2.carbon.identity.external.api.client.api.exception.APIClientException;
import org.wso2.carbon.identity.external.api.client.api.model.APIAuthentication;
import org.wso2.carbon.identity.external.api.client.api.model.APIClientConfig;
import org.wso2.carbon.identity.external.api.client.api.model.APIInvocationConfig;
import org.wso2.carbon.identity.external.api.client.api.model.APIRequestContext;
import org.wso2.carbon.identity.external.api.client.api.model.APIResponse;
import org.wso2.carbon.identity.external.api.client.api.service.AbstractAPIClientManager;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class to fetch and parse SAML metadata from a URL and extract signing certificates.
 */
public class SAMLMetadataCertificateResolver extends AbstractAPIClientManager {

    private static final Log LOG = LogFactory.getLog(SAMLMetadataCertificateResolver.class);

    private static final int HTTP_OK = 200;

    private static final SAMLMetadataCertificateResolver INSTANCE;

    static {
        try {
            INSTANCE = new SAMLMetadataCertificateResolver();
        } catch (APIClientException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private SAMLMetadataCertificateResolver() throws APIClientException {

        super(new APIClientConfig.Builder().build());
    }

    /**
     * Returns the singleton {@link SAMLMetadataCertificateResolver} instance.
     *
     * @return The singleton instance.
     */
    public static SAMLMetadataCertificateResolver getInstance() {

        return INSTANCE;
    }

    /**
     * Fetches the SAML metadata from the given URL, validates that its root EntityDescriptor has a matching
     * entity ID, and extracts all signing X.509 certificates.
     *
     * @param metadataUrl The URL of the SAML metadata endpoint.
     * @param entityId    The entity ID to match against the metadata's EntityDescriptor.
     * @return A {@link RemoteCertificate} containing the resolved signing certificates together with the validUntil
     *         and cacheDuration values from the metadata and the timestamp of this retrieval.
     * @throws SAMLSSOException If the URL is invalid, the entity ID does not match, the metadata cannot be
     *                          fetched, the XML cannot be parsed, or a certificate value cannot be decoded.
     */
    public RemoteCertificate getSigningCertificatesFromMetadata(String metadataUrl,
            String entityId) throws SAMLSSOException {

        if (StringUtils.isBlank(metadataUrl)) {
            throw new SAMLSSOException(METADATA_URL_BLANK.getCode(), METADATA_URL_BLANK.getMessage());
        }

        String rawMetadata = fetchMetadata(metadataUrl);

        EntityDescriptor entityDescriptor = toEntityDescriptor(rawMetadata, metadataUrl);

        if (!entityId.equals(entityDescriptor.getEntityID())) {
            throw new SAMLSSOException(METADATA_ENTITY_ID_MISMATCH.getCode(),
                    String.format(METADATA_ENTITY_ID_MISMATCH.getMessage(),
                            entityId, entityDescriptor.getEntityID()));
        }

        List<X509Certificate> certificates = extractCertificates(entityDescriptor);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Extracted " + certificates.size() + " signing certificate(s) from SAML metadata at: "
                + metadataUrl);
        }

        Instant validUntil = entityDescriptor.getValidUntil() != null
                ? Instant.ofEpochMilli(entityDescriptor.getValidUntil().getMillis())
                : null;

        Duration cacheDuration = entityDescriptor.getCacheDuration() != null
                ? Duration.ofMillis(entityDescriptor.getCacheDuration())
                : null;

        return new RemoteCertificate.Builder(certificates)
                .validUntil(validUntil)
                .cacheDuration(cacheDuration)
                .lastRetrievedAt(null)
                .build();
    }

    /**
     * Issues a GET request to metadataUrl using the {@link AbstractAPIClientManager} HTTP client and returns
     * the raw response body.
     *
     * @param metadataUrl Validated URL.
     * @return Raw metadata XML string.
     * @throws SAMLSSOException On HTTP or I/O error.
     */
    private String fetchMetadata(String metadataUrl) throws SAMLSSOException {

        try {
            APIAuthentication authentication = new APIAuthentication.Builder()
                    .authType(APIAuthentication.AuthType.NONE)
                    .build();

            APIRequestContext requestContext = new APIRequestContext.Builder()
                    .httpMethod(APIRequestContext.HttpMethod.GET)
                    .apiAuthentication(authentication)
                    .endpointUrl(metadataUrl)
                    .build();

            APIInvocationConfig invocationConfig = new APIInvocationConfig();

            APIResponse response = callAPI(requestContext, invocationConfig);

            if (response.getStatusCode() != HTTP_OK) {
                throw new SAMLSSOException(METADATA_FETCH_HTTP_ERROR.getCode(),
                        String.format(METADATA_FETCH_HTTP_ERROR.getMessage(),
                                response.getStatusCode(), metadataUrl));
            }

            String body = response.getResponseBody();
            if (StringUtils.isBlank(body)) {
                throw new SAMLSSOException(METADATA_EMPTY_RESPONSE_BODY.getCode(),
                        String.format(METADATA_EMPTY_RESPONSE_BODY.getMessage(), metadataUrl));
            }

            return body;
        } catch (APIClientException e) {
            throw new SAMLSSOException(METADATA_FETCH_FAILED.getCode(),
                    String.format(METADATA_FETCH_FAILED.getMessage(), metadataUrl), e);
        }
    }

    /**
     * Parses a raw SAML metadata XML string into an OpenSAML {@link EntityDescriptor}.
     *
     * @param rawMetadata Raw XML string from the metadata endpoint.
     * @param metadataUrl Original URL, used only for error messages.
     * @return Parsed {@link EntityDescriptor}.
     * @throws SAMLSSOException If the XML cannot be parsed or is not a SAML EntityDescriptor.
     */
    private EntityDescriptor toEntityDescriptor(String rawMetadata, String metadataUrl) throws SAMLSSOException {

        XMLObject xmlObject = SSOUtils.unmarshall(rawMetadata);
        if (!(xmlObject instanceof EntityDescriptor)) {
            throw new SAMLSSOException(METADATA_NOT_ENTITY_DESCRIPTOR.getCode(),
                    String.format(METADATA_NOT_ENTITY_DESCRIPTOR.getMessage(),
                            metadataUrl, xmlObject.getClass().getName()));
        }
        return (EntityDescriptor) xmlObject;
    }

    /**
     * Extracts every signing X.509 certificate from the EntityDescriptor and decodes them into Java
     * {@link X509Certificate} objects.
     *
     * @param entityDescriptor Parsed metadata root.
     * @return Mutable list of decoded {@link X509Certificate} objects.
     * @throws SAMLSSOException If a certificate value cannot be decoded.
     */
    private List<X509Certificate> extractCertificates(EntityDescriptor entityDescriptor) throws SAMLSSOException {

        List<X509Certificate> certificates = new ArrayList<>();

        List<IDPSSODescriptor> idpDescriptors = entityDescriptor
                .getRoleDescriptors(IDPSSODescriptor.DEFAULT_ELEMENT_NAME)
                .stream()
                .filter(IDPSSODescriptor.class::isInstance)
                .map(IDPSSODescriptor.class::cast)
                .collect(Collectors.toList());

        if (idpDescriptors.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No IDPSSODescriptor found in SAML EntityDescriptor for entity: "
                            + entityDescriptor.getEntityID());
            }
            return certificates;
        }

        for (IDPSSODescriptor idpDescriptor : idpDescriptors) {
            if (idpDescriptor.getKeyDescriptors() == null) {
                continue;
            }
            for (KeyDescriptor keyDescriptor : idpDescriptor.getKeyDescriptors()) {
                if (keyDescriptor.getUse() != UsageType.SIGNING) {
                    continue;
                }
                if (keyDescriptor.getKeyInfo() == null) {
                    continue;
                }
                List<X509Data> x509DataList = keyDescriptor.getKeyInfo().getX509Datas();
                if (x509DataList == null) {
                    continue;
                }
                for (X509Data x509Data : x509DataList) {
                    if (x509Data.getX509Certificates() == null) {
                        continue;
                    }
                    for (org.opensaml.xmlsec.signature.X509Certificate x509CertElement 
                            : x509Data.getX509Certificates()) {

                        String certValue = x509CertElement.getValue();
                        if (StringUtils.isBlank(certValue)) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Encountered a blank X509Certificate value in SAML metadata — skipping.");
                            }
                            continue;
                        }

                        X509Certificate cert = decodeCertificate(certValue.trim());
                        certificates.add(cert);
                    }
                }
            }
        }

        return certificates;
    }

    /**
     * Decodes a Base64-encoded DER X.509 certificate value from the metadata into a Java {@link X509Certificate}.
     *
     * @param base64Der Base64-encoded DER bytes.
     * @return Decoded and parsed {@link X509Certificate}.
     * @throws SAMLSSOException If the value does not encode a valid X.509 certificate.
     */
    private X509Certificate decodeCertificate(String base64Der) throws SAMLSSOException {

        try {
            String cleaned = base64Der.replaceAll("\\s+", "");
            return (X509Certificate) IdentityApplicationManagementUtil.decodeCertificate(cleaned);
        } catch (CertificateException e) {
            throw new SAMLSSOException(METADATA_CERT_DECODE_FAILED.getCode(),
                    METADATA_CERT_DECODE_FAILED.getMessage(), e);
        }
    }

}
