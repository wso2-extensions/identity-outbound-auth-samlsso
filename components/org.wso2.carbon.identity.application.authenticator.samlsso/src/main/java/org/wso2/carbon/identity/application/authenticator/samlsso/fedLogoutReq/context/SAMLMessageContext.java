package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.context;

import org.opensaml.saml2.core.LogoutRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request.SAMLLogoutRequest;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Map;

public class SAMLMessageContext <T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext{

    private String sessionID;
    private IdentityProvider federatedIdp;
    private LogoutRequest logoutReq;
    private Boolean validStatus;
    private String response;
    private String acsUrl;
    private Map<String,String> fedIdpConfigs;
    private X509Certificate idpCertificate;


    public SAMLMessageContext(IdentityRequest request,Map<T1, T2> parameters) {
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

    public String getAcsUrl() { return acsUrl; }

    public void setAcsUrl(String acsUrl) { this.acsUrl = acsUrl; }

    public IdentityProvider getFederatedIdp() {
        return federatedIdp;
    }

    public void setFederatedIdp(IdentityProvider federatedIdp) {
        this.federatedIdp = federatedIdp;
    }

    public void setLogoutReq(LogoutRequest logoutReq) {
        this.logoutReq = logoutReq;
    }

    public LogoutRequest getLogoutReq() {
        return logoutReq;
    }

    public String getSamlRequest() {
        return request.getParameter(SAMLConstants.SAML_REQUEST);
    }

    public Boolean getValidStatus() {
        return validStatus;
    }

    public void setValidStatus(Boolean validStatus) { this.validStatus = validStatus; }

    public String getResponse() { return response; }

    public void setResponse(String response) { this.response = response; }

    public Map<String,String> getFedIdpConfigs() {
        return fedIdpConfigs;
    }

    public void setFedIdpConfigs(Map<String,String> fedIdpConfigs) {
        this.fedIdpConfigs = fedIdpConfigs;
    }

    public String getRelayState() {
        return request.getParameter(SAMLConstants.RELAY_STATE);
    }

    public void setIdpCertificate(X509Certificate idpCertificate) {
        this.idpCertificate = idpCertificate;
    }

    public X509Certificate getIdpCertificate() {
        return idpCertificate;
    }
}
