package org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.response;

import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authenticator.samlsso.fedLogoutReq.exception.SAMLIdentityException;

import javax.servlet.http.HttpServletResponse;

public class SAMLLogoutResponseFactory extends HttpIdentityResponseFactory {
    @Override
    public boolean canHandle(IdentityResponse identityResponse) {

        if(identityResponse instanceof SAMLLogoutResponse) {
            return true;
        }
        return false;

    }

    @Override
    public boolean canHandle(FrameworkException exception) {
        if(exception instanceof SAMLIdentityException){
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder responseBuilder =
                new HttpIdentityResponse.HttpIdentityResponseBuilder();
        create(responseBuilder,identityResponse);
        return responseBuilder;
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        SAMLLogoutResponse response = (SAMLLogoutResponse)identityResponse;
        String samlPostPage = generateSamlPostPageFromTemplate(response.getAcsUrl(), response.getResponse(), response.getRelayState());
        builder.setBody(samlPostPage);
        builder.setStatusCode(HttpServletResponse.SC_OK);
        builder.setRedirectURL(response.getAcsUrl());
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkException exception) {

        HttpIdentityResponse.HttpIdentityResponseBuilder errorResponseBuilder =
            new HttpIdentityResponse.HttpIdentityResponseBuilder();
        SAMLIdentityException samlException = (SAMLIdentityException)exception;
        String samlPostPage= generateSamlPostPageFromTemplate(samlException.getAcsUrl(),samlException.getExceptionMessage(),samlException.getRelayState());
        errorResponseBuilder.setBody(samlPostPage);
        errorResponseBuilder.setStatusCode(HttpServletResponse.SC_OK);
        errorResponseBuilder.setBody(samlException.getExceptionMessage());
        errorResponseBuilder.setRedirectURL(samlException.getAcsUrl());
        return errorResponseBuilder;
    }


    public String generateSamlPostPageFromTemplate(String acUrl, String samlMessage, String relayState){

        StringBuilder out = new StringBuilder();
        out.append("<html>");
        out.append("<body>");
        out.append("<p>You are now redirected back to " + Encode.forHtmlContent(acUrl));
        out.append(" If the redirection fails, please click the post button.</p>");
        out.append("<form method='post' action='" + Encode.forHtmlAttribute(acUrl) + "'>");
        out.append("<p>");
        out.append("<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(samlMessage) + "'>");

        if ( relayState!= null) {
            out.append("<input type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState) +
                "'>");
        }
        out.append("<button type='submit'>POST</button>");
        out.append("</p>");
        out.append("</form>");
        out.append("<script type='text/javascript'>");
        out.append("document.forms[0].submit();");
        out.append("</script>");
        out.append("</body>");
        out.append("</html>");
        return out.toString();
    }
}
