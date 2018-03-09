/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import com.ctc.wstx.stax.WstxInputFactory;
import com.sun.org.apache.xpath.internal.jaxp.XPathFactoryImpl;
import org.apache.xerces.dom.CoreDOMImplementationImpl;
import org.apache.xerces.jaxp.DocumentBuilderFactoryImpl;
import org.apache.xerces.util.SecurityManager;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.xpath.XPathFactory;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Mock Utils
 */
public class MockUtils {

    public static void mockXPathFactory() {

        mockStatic(XPathFactory.class);
        XPathFactory xPathFactory = new XPathFactoryImpl();
        when(XPathFactory.newInstance()).thenReturn(xPathFactory);
    }

    public static void mockXMLInputFactory() {

        mockStatic(XMLInputFactory.class);
        when(XMLInputFactory.newInstance()).thenReturn(new WstxInputFactory());
    }

    public static void mockDocumentBuilderFactory() throws ParserConfigurationException {

        DocumentBuilderFactory documentBuilderFactory = getSecuredDocumentBuilderFactory();
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getSecuredDocumentBuilderFactory()).thenReturn(documentBuilderFactory);

        mockStatic(DocumentBuilderFactory.class);
        when(DocumentBuilderFactory.newInstance()).thenReturn(new DocumentBuilderFactoryImpl());
    }

    public static void mockDOMImplementationRegistry(DOMImplementationRegistry mockedDomImplementationRegistry)
            throws Exception {

        mockStatic(DOMImplementationRegistry.class);
        when(DOMImplementationRegistry.newInstance()).thenReturn(mockedDomImplementationRegistry);
        when(mockedDomImplementationRegistry.getDOMImplementation("LS")).thenReturn(new CoreDOMImplementationImpl());
    }

    private static DocumentBuilderFactory getSecuredDocumentBuilderFactory() throws ParserConfigurationException {

        DocumentBuilderFactory builderFactory = new DocumentBuilderFactoryImpl();
        builderFactory.setNamespaceAware(true);
        builderFactory.setXIncludeAware(false);
        builderFactory.setExpandEntityReferences(false);
        builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        builderFactory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(0);
        builderFactory.setAttribute("http://apache.org/xml/properties/security-manager", securityManager);
        return builderFactory;
    }
}
