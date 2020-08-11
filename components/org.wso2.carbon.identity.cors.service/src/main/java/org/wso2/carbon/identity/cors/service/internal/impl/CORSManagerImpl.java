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

package org.wso2.carbon.identity.cors.service.internal.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.cors.mgt.core.constant.ErrorMessages;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSConfigurationDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSOriginDAO;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceServerException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSOrigin;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.service.internal.CORSServiceHolder;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCache;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCacheEntry;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCacheKey;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCache;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCacheEntry;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCacheKey;
import org.wso2.carbon.identity.cors.service.internal.function.CORSOriginToValidatedOrigin;
import org.wso2.carbon.identity.cors.service.internal.store.ServerCORSStore;

import java.util.List;
import java.util.stream.Collectors;

/**
 * CORSManager implementation.
 */
public class CORSManagerImpl implements CORSManager {

    private static final Log log = LogFactory.getLog(CORSManagerImpl.class);

    @Override
    public ValidatedOrigin[] getCORSOrigins(String tenantDomain) throws CORSManagementServiceServerException {

        ValidatedOrigin[] cachedResult = getCORSOriginsFromCache(tenantDomain);
        if (cachedResult != null) {
            return cachedResult;
        }

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            List<CORSOrigin> corsOriginList = getCORSOriginDAO().getCORSOriginsByTenantId(tenantId);

            List<ValidatedOrigin> validatedOriginList = ServerCORSStore.getServerCORSOrigins();
            if (!corsOriginList.isEmpty()) {
                validatedOriginList.addAll(corsOriginList.stream()
                        .map(new CORSOriginToValidatedOrigin()).collect(Collectors.toList()));
            }

            ValidatedOrigin[] validatedOriginArray = validatedOriginList.toArray(new ValidatedOrigin[0]);

            // Add to cache.
            addCORSOriginsToCache(validatedOriginArray, tenantDomain);

            return validatedOriginArray;
        } catch (CORSManagementServiceException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getDescription(), tenantDomain), e);
        }
    }

    @Override
    public CORSConfiguration getCORSConfiguration(String tenantDomain) throws CORSManagementServiceException {

        CORSConfiguration cachedResult = getCORSConfigurationFromCache(tenantDomain);
        if (cachedResult != null) {
            return cachedResult;
        }

        try {
            CORSConfiguration corsConfiguration = getCORSConfigurationDAO()
                    .getCORSConfigurationByTenantDomain(tenantDomain);

            // Add to cache.
            addCORSConfigurationToCache(corsConfiguration, tenantDomain);

            return corsConfiguration;
        } catch (CORSManagementServiceException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_CONFIG_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_CONFIG_RETRIEVE.getDescription(), tenantDomain), e);
        }
    }

    /**
     * Returns a CORSOriginDAO instance.
     *
     * @return A CORSOriginDAO instance.
     */
    private CORSOriginDAO getCORSOriginDAO() {

        return CORSServiceHolder.getInstance().getCorsOriginDAO();
    }

    /**
     * Returns a CORSConfigurationDAO instance.
     *
     * @return A CORSConfigurationDAO instance.
     */
    private CORSConfigurationDAO getCORSConfigurationDAO() {

        return CORSServiceHolder.getInstance().getCorsConfigurationDAO();
    }

    /**
     * Add CORS origins to the cache.
     *
     * @param validatedOrigins The validated origins that should be added to the cache.
     * @param tenantDomain     The tenant domain specific to the cache entry.
     */
    private void addCORSOriginsToCache(ValidatedOrigin[] validatedOrigins, String tenantDomain) {

        CORSOriginCacheKey cacheKey = new CORSOriginCacheKey(tenantDomain);
        CORSOriginCacheEntry cacheEntry = new CORSOriginCacheEntry(validatedOrigins);

        if (log.isDebugEnabled()) {
            log.debug("Adding CORS origins to Cache with Key: " + tenantDomain);
        }

        CORSOriginCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    /**
     * Get CORS origins from the cache.
     *
     * @param tenantDomain The tenant domain specific to the cache entry.
     * @return Returns an array of {@code ValidatedOrigin}(s) if the cached origins are found for the tenant.
     * Else return {@code null}.
     */
    private ValidatedOrigin[] getCORSOriginsFromCache(String tenantDomain) {

        CORSOriginCacheKey cacheKey = new CORSOriginCacheKey(tenantDomain);
        CORSOriginCache cache = CORSOriginCache.getInstance();
        CORSOriginCacheEntry cacheEntry = cache.getValueFromCache(cacheKey);
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry not found for cache key:" + tenantDomain);
            }
            return null;
        }

        if (cacheEntry.getValidatedOrigins() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find CORS origins in the cache entry.");
            }
            return null;
        }

        return cacheEntry.getValidatedOrigins();
    }

    /**
     * Add CORS configurations to the cache.
     *
     * @param corsConfiguration The cors configuration that should be added to the cache.
     * @param tenantDomain      The tenant domain specific to the cache entry.
     */
    private void addCORSConfigurationToCache(CORSConfiguration corsConfiguration, String tenantDomain) {

        CORSConfigurationCacheKey cacheKey = new CORSConfigurationCacheKey(tenantDomain);
        CORSConfigurationCacheEntry cacheEntry = new CORSConfigurationCacheEntry(corsConfiguration);

        if (log.isDebugEnabled()) {
            log.debug("Adding CORS configuration to Cache with Key: " + tenantDomain);
        }

        CORSConfigurationCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    /**
     * Get CORS configuration from the cache.
     *
     * @param tenantDomain The tenant domain specific to the cache entry.
     * @return Returns an instance of {@code CORSConfiguration}(s) if the cached CORS configuration is found for the
     * tenant. Else return {@code null}.
     */
    private CORSConfiguration getCORSConfigurationFromCache(String tenantDomain) {

        CORSConfigurationCacheKey cacheKey = new CORSConfigurationCacheKey(tenantDomain);
        CORSConfigurationCache cache = CORSConfigurationCache.getInstance();
        CORSConfigurationCacheEntry cacheEntry = cache.getValueFromCache(cacheKey);
        if (cacheEntry == null) {
            if (log.isDebugEnabled()) {
                log.debug("Cache entry not found for cache key :" + tenantDomain);
            }
            return null;
        }

        if (cacheEntry.getCorsConfiguration() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Could not find CORS configuration in the cache entry.");
            }
            return null;
        }

        return cacheEntry.getCorsConfiguration();
    }
}
