/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.logout.context;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.logout.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.io.Serializable;
import java.util.Map;

/**
 * This class holds data of the federated IdP initiated logout flow.
 */
public class SAMLMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    private String acsUrl;
    private String response;
    private String sessionID;
    private String idpSessionID;
    private String tenantDomain;
    private String federatedIdpId;
    private Boolean validStatus;
    private IdentityProvider federatedIdP;
    private Map<String, String> fedIdPConfigs;

    public SAMLMessageContext(IdentityRequest request, Map<T1, T2> parameters) {

        super(request, parameters);
    }

    public SAMLLogoutRequest getSAMLLogoutRequest() {

        return (SAMLLogoutRequest) request;
    }

    public String getSessionID() {

        return sessionID;
    }

    public void setSessionID(String sessionID) {

        this.sessionID = sessionID;
    }

    public String getIdPSessionID() {

        return idpSessionID;
    }

    public void setIdPSessionID(String idpSessionID) {

        this.idpSessionID = idpSessionID;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }

    public String getAcsUrl() {

        return acsUrl;
    }

    public void setAcsUrl(String acsUrl) {

        this.acsUrl = acsUrl;
    }

    public IdentityProvider getFederatedIdP() {

        return federatedIdP;
    }

    public void setFederatedIdP(IdentityProvider federatedIdP) {

        this.federatedIdP = federatedIdP;
    }

    public Boolean getValidStatus() {

        return validStatus;
    }

    public void setValidStatus(Boolean validStatus) {

        this.validStatus = validStatus;
    }

    public String getResponse() {

        return response;
    }

    public void setResponse(String response) {

        this.response = response;
    }

    public Map<String, String> getFedIdPConfigs() {

        return fedIdPConfigs;
    }

    public void setFedIdPConfigs(Map<String, String> fedIdPConfigs) {

        this.fedIdPConfigs = fedIdPConfigs;
    }

    public String getRelayState() {

        return request.getParameter(SSOConstants.RELAY_STATE);
    }

    public String getFederatedIdpId() {

        return federatedIdpId;
    }

    public void setFederatedIdpId(String federatedIdpId) {

        this.federatedIdpId = federatedIdpId;
    }
}
