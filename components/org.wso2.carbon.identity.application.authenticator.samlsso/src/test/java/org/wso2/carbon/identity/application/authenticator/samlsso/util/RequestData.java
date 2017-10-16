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

package org.wso2.carbon.identity.application.authenticator.samlsso.util;

/**
 * SAML Request Data.
 */
public class RequestData {

    private String spEntityId;

    private boolean isForce;

    private boolean isPassive;

    private String httpBinding;

    private String acsUrl;

    private String idPUrl;

    private boolean enableExtensions;

    private String acsIndex;

    private String sessionIndex;

    private String user;

    private boolean signRequest;

    private String protocolBinding;

    private boolean includeCertProperty;

    private String forceAuthenticateProp;

    private boolean authenticatorConfigAvailable;

    private String includeNameIDPolicyProp;

    private boolean includePostParam;

    public RequestData(String spEntityId, boolean isForce, boolean isPassive, String httpBinding, String acsUrl,
                       String idPUrl, boolean enableExtensions, String acsIndex) {

        this.spEntityId = spEntityId;
        this.isForce = isForce;
        this.isPassive = isPassive;
        this.httpBinding = httpBinding;
        this.acsUrl = acsUrl;
        this.idPUrl = idPUrl;
        this.enableExtensions = enableExtensions;
        this.acsIndex = acsIndex;
    }

    public RequestData(String spEntityId, boolean isForce, boolean isPassive, String httpBinding, String acsUrl,
                       String idPUrl, boolean enableExtensions, String acsIndex, boolean signRequest, String
                               protocolBinding, boolean includeCertProperty, String forceAuthenticateProp, boolean
                               authenticatorConfigAvailable, String includeNameIDPolicyProp) {

        this.spEntityId = spEntityId;
        this.isForce = isForce;
        this.isPassive = isPassive;
        this.httpBinding = httpBinding;
        this.acsUrl = acsUrl;
        this.idPUrl = idPUrl;
        this.enableExtensions = enableExtensions;
        this.acsIndex = acsIndex;
        this.signRequest = signRequest;
        this.protocolBinding = protocolBinding;
        this.includeCertProperty = includeCertProperty;
        this.forceAuthenticateProp = forceAuthenticateProp;
        this.authenticatorConfigAvailable = authenticatorConfigAvailable;
        this.includeNameIDPolicyProp = includeNameIDPolicyProp;
    }

    public RequestData(String spEntityId, boolean isForce, boolean isPassive, String httpBinding, String acsUrl,
                       String idPUrl, boolean enableExtensions, String acsIndex, boolean signRequest, String
                               protocolBinding, boolean includeCertProperty, String forceAuthenticateProp, boolean
                               authenticatorConfigAvailable, String includeNameIDPolicyProp, boolean includePostParam) {

        this.spEntityId = spEntityId;
        this.isForce = isForce;
        this.isPassive = isPassive;
        this.httpBinding = httpBinding;
        this.acsUrl = acsUrl;
        this.idPUrl = idPUrl;
        this.enableExtensions = enableExtensions;
        this.acsIndex = acsIndex;
        this.signRequest = signRequest;
        this.protocolBinding = protocolBinding;
        this.includeCertProperty = includeCertProperty;
        this.forceAuthenticateProp = forceAuthenticateProp;
        this.authenticatorConfigAvailable = authenticatorConfigAvailable;
        this.includeNameIDPolicyProp = includeNameIDPolicyProp;
        this.includePostParam = includePostParam;
    }

    public RequestData(String spEntityId, String idPUrl, String sessionIndex, String user) {

        this.spEntityId = spEntityId;
        this.idPUrl = idPUrl;
        this.sessionIndex = sessionIndex;
        this.user = user;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public boolean isForce() {
        return isForce;
    }

    public void setForce(boolean force) {
        isForce = force;
    }

    public boolean isPassive() {
        return isPassive;
    }

    public void setPassive(boolean passive) {
        isPassive = passive;
    }

    public String getHttpBinding() {
        return httpBinding;
    }

    public void setHttpBinding(String httpBinding) {
        this.httpBinding = httpBinding;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public void setAcsUrl(String acsUrl) {
        this.acsUrl = acsUrl;
    }

    public String getIdPUrl() {
        return idPUrl;
    }

    public void setIdPUrl(String idPUrl) {
        this.idPUrl = idPUrl;
    }

    public boolean isEnableExtensions() {
        return enableExtensions;
    }

    public void setEnableExtensions(boolean enableExtensions) {
        this.enableExtensions = enableExtensions;
    }

    public String getAcsIndex() {
        return acsIndex;
    }

    public void setAcsIndex(String acsIndex) {
        this.acsIndex = acsIndex;
    }

    public String getSessionIndex() {
        return sessionIndex;
    }

    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public boolean isSignRequest() {
        return signRequest;
    }

    public void setSignRequest(boolean signRequest) {
        this.signRequest = signRequest;
    }

    public String getProtocolBinding() {
        return protocolBinding;
    }

    public void setProtocolBinding(String protocolBinding) {
        this.protocolBinding = protocolBinding;
    }

    public boolean isIncludeCertProperty() {

        return includeCertProperty;
    }

    public void setIncludeCertProperty(boolean includeCertProperty) {
        this.includeCertProperty = includeCertProperty;
    }

    public String getForceAuthenticateProp() {
        return forceAuthenticateProp;
    }

    public void setForceAuthenticateProp(String forceAuthenticateProp) {
        this.forceAuthenticateProp = forceAuthenticateProp;
    }

    public boolean isAuthenticatorConfigAvailable() {
        return authenticatorConfigAvailable;
    }

    public void setAuthenticatorConfigAvailable(boolean authenticatorConfigAvailable) {
        this.authenticatorConfigAvailable = authenticatorConfigAvailable;
    }

    public String getIncludeNameIDPolicyProp() {
        return includeNameIDPolicyProp;
    }

    public void setIncludeNameIDPolicyProp(String includeNameIDPolicyProp) {
        this.includeNameIDPolicyProp = includeNameIDPolicyProp;
    }

    public boolean isIncludePostParam() {
        return includePostParam;
    }

    public void setIncludePostParam(boolean includePostParam) {
        this.includePostParam = includePostParam;
    }
}
