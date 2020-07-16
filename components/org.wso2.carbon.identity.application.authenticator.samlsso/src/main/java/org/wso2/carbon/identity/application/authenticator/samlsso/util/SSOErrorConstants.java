/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authenticator.samlsso.util;

public class SSOErrorConstants {

    /**
     * Relevant error messages and error codes.
     */
    public enum ErrorMessages {

        // SAML Assertion related Exceptions
        UNABLE_TO_DECRYPT_THE_SAML_ASSERTION("SAM-65001", "Unable to decrypt the SAML Assertion"),
        // Not found related Exceptions
        FEDERATED_USER_IDENTIFIER_NOT_FOUND("SAM-65021",
                "Cannot find federated User Identifier post authentication handler"),
        CLASS_NOT_FOUND_EXCEPTION("SAM-65022", "Cannot find the class definition"),
        // Signature related Exceptions
        ADDING_SIGNATURE_TO_HTTP_QUERY_STRING_FAILED("SAM-65041",
                "Error while adding signature to HTTP query string"),
        SIGNING_SAML_REQUEST_FAILED("SAM-65042", "Error while signing the SAML Request"),
        UNABLE_TO_SIGN_QUERY_STRING("SAM-65043", "Unable to sign query string"),
        IDP_CERTIFICATE_MISSING("SAM-65044",
                "IdP certificate is needed for AuthnRequest signing in POST binding"),
        // Tenant and IDP  related Exceptions
        INVALID_IDP_ID("SAM-65061",
                "Identity provider with entity id '%s' is not registered in the system."),
        IO_ERROR("SAM-65062", "IO_ERROR"),
        // keystore related Exceptions
        UNABLE_TO_LOCATE_KEYSTORE("SAM-65071", "Unable to locate keystore"),
        UNABLE_TO_READ_KEYSTORE("SAM-65072", "Unable to read keystore"),
        CONFIGURED_PRIVATE_KEY_IS_INVALID("SAM-65073",
                "Configured signing KeyStore private key is invalid"),
        CONFIGURED_PUBLIC_KEY_IS_INVALID("SAM-65074",
                "Configured signing KeyStore public key is invalid"),
        UNABLE_TO_LOAD_KEYSTORE("SAM-65075", "Unable to load keystore"),
        // key and certificate related Exceptions
        UNABLE_TO_READ_CERTIFICATE("SAM-65091", "Unable to read certificate"),
        INVALID_ALGORITHM("SAM-65092", "Unable to load algorithm"),
        UNABLE_TO_LOAD_KEY("SAM-65093", "Unable to load key"),
        RETRIEVING_PRIVATE_KEY_AND_CERTIFICATE_FOR_TENANT_FAILED("SAM-65094",
                "Error retrieving private key and the certificate for tenant %s"),
        CANNOT_FIND_THE_PRIVATE_KEY_FOR_TENANT("SAM-65095",
                "Cannot find the private key for tenant %s"),
        CANNOT_FIND_THE_CERTIFICATE("SAM-65096", "Cannot find the certificate."),
        // Other Exceptions
        ILLEGAL_ACCESS("SAM-60131", "Error while illegal access"),
        SAML_RESPONSE_STATUS_CODE_MISMATCHED_WITH_SUCCESS_CODE("SAM-60132", "Received an error SAML response."),
        ARTIFACT_RESPONSE_RESOLUTION_FAILED("SAM-60133", "Error when getting the Artifact Response."),
        INVALID_SINGLE_LOGOUT_SAML_REQUEST("SAM-60134", "Invalid Single Logout SAML Request"),
        // SAML Assertion related Exceptions
        SAML_ASSERTION_NOT_FOUND_IN_RESPONSE("SAM-60001", "SAML Assertion is not found in the Response"),
        AUDIENCE_RESTRICTION_VALIDATION_FAILED("SAM-60002",
                "SAML Assertion Audience Restriction validation failed"),
        PROCESSING_SAML2_MULTIPLE_ASSERTION_ELEMENT_FOUND("SAM-60003",
                "Error occurred while processing SAML2 response. Invalid schema for the SAML2 response. Multiple Response elements found."),
        SIGNATURE_ELEMENT_NOT_FOUND_IN_SAML_ASSERTION_WHILE_SIGNING_ENABLED("SAM-60004",
                "SAMLAssertion signing is enabled, but signature element not found in SAML Assertion element."),
        NOT_BEFORE_CONDITION_NOT_MET("SAM-60005",
                "Failed to meet SAML Assertion Condition 'Not Before'"),
        NOT_ON_OR_BEFORE_CONDITION_NOT_MET("SAM-60006",
                "Failed to meet SAML Assertion Condition 'Not On Or After'"),
        IDP_SESSION_ID_NOT_FOUND_FOR_SLO("SAM-60007",
                "Single Logout is enabled but IdP Session ID not found in SAML Assertion"),
        // Not found related Exceptions
        SUBJECT_NAME_NOT_FOUND_IN_RESPONSE("SAM-60021",
                "SAML Response does not contain the name of the subject"),
        INVALID_SCHEMA_FOR_THE_SAML_2_RESPONSE("SAM-60022",
                "Error occurred while processing SAML2 response. Invalid schema for the SAML2 response. Multiple Response elements found."),
        AUDIENCES_NOT_FOUND("SAM-60023",
                "SAML Response's AudienceRestriction doesn't contain Audiences"),
        SAML_CONDITIONS_NOT_FOUND("SAM-60024", "SAML Response doesn't contain Conditions"),
        // Signature related Exceptions
        SIGNATURE_ELEMENT_NOT_FOUND_WHILE_ENABLED("SAM-60041",
                "SAMLResponse signing is enabled, but signature element not found in SAML Response element."),
        SIGNATURE_ELEMENT_NOT_FOUND_IN_ARTIFACT_RESPONSE_WHILE_ENABLED(
                "SAM-60042",
                "Artifact Response signing is enabled, but signature element not found in Artifact Response element."),
        AUDIENCE_RESTRICTION_NOT_FOUND("SAM-60043",
                "SAML Response doesn't contain AudienceRestrictions"),
        SIGNATURE_NOT_CONFIRM_TO_SAML_SIGNATURE_PROFILE("SAM-60044",
                "Signature do not confirm to SAML signature profile. Possible XML Signature Wrapping Attack!"),
        SIGNATURE_VALIDATION_FAILED_FOR_SAML_RESPONSE("SAM-60045",
                "Signature validation failed for SAML Response"),
        // Tenant and IDP  related Exceptions
        RETRIEVING_TENANT_ID_FAILED("SAM-60061",
                "Exception occurred while retrieving Tenant ID from tenant domain %S"),
        // key and certificate related Exceptions
        RETRIEVING_THE_CERTIFICATE_FAILED("SAM-60091", "Retrieving the certificate"),
        // Decoding and Encoding related Exceptions
        UNABLE_TO_PROCESS_SAML_OBJECT_TYPE("SAM-65111", "Unable to process unknown SAML object type."),
        URL_ENCODING_RELAY_STATE("SAM-65112", "Error occurred while url encoding RelayState"),
        UNSUPPORTED_ENCODING_EXCEPTION("SAM-65113", "UnsupportedEncodingException"),
        UNMARSHALLING_SAML_REQUEST_ENCODED_STRING_FAILED("SAM-65114",
                "Error in unmarshalling SAML Request from the encoded String"),
        MARSHALLING_SAML_REQUEST_FOR_SIGNING_FAILED("SAM-65115",
                "Error while marshalling the SAML Request for signing"),
        // Other Exceptions
        HTTP_POST_NOT_SUPPORTED("SAM-65131", "HTTP-POST is not supported"),
        INSTANTIATION_FAILED("SAM-65132", "Error while instantiation"),
        UNABLE_TO_RETRIEVE_BUILDER_FOR_OBJECT_QNAME("SAM-65133",
                "Unable to retrieve builder for object QName %s");

        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s - %s", code, message);
        }
    }
}
