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

package org.wso2.carbon.identity.application.authenticator.samlsso.cache;

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for {@link SAMLCertCache}.
 */
public class SAMLCertCacheKey extends CacheKey {

    private static final long serialVersionUID = -3428667399593874682L;

    private final String metadataUrl;

    public SAMLCertCacheKey(String metadataUrl) {

        this.metadataUrl = metadataUrl;
    }

    /**
     * Returns the metadata URL that serves as the cache key.
     *
     * @return The SAML metadata URL.
     */
    public String getMetadataUrl() {

        return metadataUrl;
    }

    @Override
    public boolean equals(Object o) {

        if (!super.equals(o)) {
            return false;
        }
        return StringUtils.equals(this.metadataUrl, ((SAMLCertCacheKey) o).getMetadataUrl());
    }

    @Override
    public int hashCode() {

        return metadataUrl.hashCode();
    }
}
