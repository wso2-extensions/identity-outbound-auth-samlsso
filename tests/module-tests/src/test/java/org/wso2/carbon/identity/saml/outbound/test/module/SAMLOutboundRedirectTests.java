package org.wso2.carbon.identity.saml.outbound.test.module;

import com.google.common.net.HttpHeaders;
import org.apache.commons.io.Charsets;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.CoreOptions;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.common.model.idp.IdentityProviderConfig;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * Tests the TestService.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLOutboundRedirectTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLOutboundRedirectTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SAMLOutboundOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(SAMLOutboundOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    @Test
    public void testSAMLFederatedAuthenticationWithRedirectBinding() {
        IdentityProviderConfig identityProviderConfig = SAMLOutboundTestUtils.getIdentityProviderConfigs
                (SAMLOutboundTestConstants.SAMPLE_IDP_NAME, bundleContext);
        identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                        .REDIRECT);
        try {
            HttpURLConnection urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT + "?" +
                    SAMLOutboundTestConstants.SAMPLE_PROTOCOL + "=true", HttpMethod.GET, false);
            String location = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Map<String, String> queryParams = org.wso2.carbon.identity.gateway.resource.util.Utils.getQueryParamMap
                    (location);
            String relayState = queryParams.get(SAML2AuthConstants.RELAY_STATE);
            String samlResponse = SAMLOutboundTestUtils.getSAMLResponse();
            samlResponse = URLEncoder.encode(samlResponse);
            urlConnection = SAMLOutboundTestUtils.request(SAMLOutboundTestConstants.GATEWAY_ENDPOINT, HttpMethod.POST,
                    true);
            String postData = "SAMLResponse=" + samlResponse + "&" + "RelayState=" + relayState;
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postData.toString().getBytes(Charsets.UTF_8));
            urlConnection.getResponseCode();
            String locationHeader = SAMLOutboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains("authenticatedUser=AuthenticatedUserName"));
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } catch (IdentityException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            identityProviderConfig.getAuthenticationConfig().getAuthenticatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.REQUEST_BINDING, SAML2AuthConstants.Config.Value
                            .POST);
        }
    }


}
