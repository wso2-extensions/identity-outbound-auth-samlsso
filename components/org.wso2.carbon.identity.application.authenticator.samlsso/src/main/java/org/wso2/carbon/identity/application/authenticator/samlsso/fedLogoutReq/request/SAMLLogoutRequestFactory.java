package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.request;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.constants.SAMLConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.base.IdentityException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


public class SAMLLogoutRequestFactory extends HttpIdentityRequestFactory {


    public SAMLLogoutRequestFactory() {
        super();
    }

    @Override
    public String getName() {
        return "SAMLLogoutRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        if(StringUtils.isNotBlank(request.getParameter(SAMLConstants.SAML_REQUEST))){
            return true;
        }
        return false;

    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request, HttpServletResponse response) {


        SAMLLogoutRequest.SAMLLogoutRequestBuilder builder = new SAMLLogoutRequest.SAMLLogoutRequestBuilder(request, response);
        try {
            create(builder, request, response);
        } catch (IdentityException e) {
            e.printStackTrace();
        }

        return builder;
    }

    public void create(SAMLLogoutRequest.SAMLLogoutRequestBuilder builder,
                       HttpServletRequest request,
                       HttpServletResponse response) throws IdentityException{

        super.create(builder, request, response);
        String idpSessionIndex = (String)request.getSession(false).getAttribute(SSOConstants.IDP_SESSION);
        String subject = (String) request.getSession().getAttribute("username");
        builder.setIdpSessionIndex(idpSessionIndex);
        builder.setSubject(subject);
        builder.isPost(StringUtils.isBlank(request.getQueryString()));

    }

}
