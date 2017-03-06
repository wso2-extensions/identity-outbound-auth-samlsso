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

package org.wso2.carbon.identity.authenticator.outbound.saml2sso.bean;

/**
 * Bean class that represents the SAML2 SSO Outbound Authenticator Configuration.
 * This class must read configuration from deployment.yaml.
 */
public class Config {

    private static volatile Config instance = new Config();

    private Config() {

    }

    public static Config getInstance() {
        return instance;
    }

    private String authnRequestPage = "<html>\n" +
                                      "\t<body>\n" +
                                      "        \t<p>You are now redirected to $url \n" +
                                      "        \tIf the redirection fails, please click the post button.</p>\n" +
                                      "\n" +
                                      "        \t<form method='post' action='$url'>\n" +
                                      "       \t\t\t<p>\n" +
                                      "                    <!--$params-->\n" +
                                      "        \t\t\t<button type='submit'>POST</button>\n" +
                                      "       \t\t\t</p>\n" +
                                      "       \t\t</form>\n" +
                                      "       \t\t<script type='text/javascript'>\n" +
                                      "        \t\tdocument.forms[0].submit();\n" +
                                      "        \t</script>\n" +
                                      "        </body>\n" +
                                      "</html>";

    public String getAuthnRequestPage() {
        return authnRequestPage;
    }

    public void setAuthnRequestPage(String authnRequestPage) {
        this.authnRequestPage = authnRequestPage;
    }

}
