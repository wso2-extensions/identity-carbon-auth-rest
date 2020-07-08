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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.cors.mgt.core.constant.ErrorMessages;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceServerException;
import org.wso2.carbon.identity.cors.mgt.core.internal.function.ResourceToCORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.internal.function.ResourcesToValidatedOrigins;
import org.wso2.carbon.identity.cors.mgt.core.internal.util.CORSConfigurationUtils;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.service.internal.CORSServiceHolder;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCache;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCacheEntry;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSConfigurationCacheKey;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCache;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCacheEntry;
import org.wso2.carbon.identity.cors.service.internal.cache.CORSOriginCacheKey;
import org.wso2.carbon.identity.cors.service.internal.store.ServerCORSStore;

import static org.wso2.carbon.identity.configuration.mgt.core.constant.ConfigurationConstants.ErrorMessages.ERROR_CODE_RESOURCE_DOES_NOT_EXISTS;
import static org.wso2.carbon.identity.cors.mgt.core.internal.Constants.CORS_CONFIGURATION_RESOURCE_NAME;
import static org.wso2.carbon.identity.cors.mgt.core.internal.Constants.CORS_CONFIGURATION_RESOURCE_TYPE_NAME;
import static org.wso2.carbon.identity.cors.mgt.core.internal.Constants.CORS_ORIGIN_RESOURCE_TYPE_NAME;

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
            FrameworkUtils.startTenantFlow(tenantDomain);

            Resources resources = getResources(CORS_ORIGIN_RESOURCE_TYPE_NAME);
            ValidatedOrigin[] validatedOrigins;
            if (resources.getResources().isEmpty()) {
                validatedOrigins = ServerCORSStore.getServerCORSOrigins();
            } else {
                validatedOrigins = new ResourcesToValidatedOrigins().apply(resources).toArray(new ValidatedOrigin[0]);
            }

            // Add to cache.
            addCORSOriginsToCache(validatedOrigins, tenantDomain);

            return validatedOrigins;
        } catch (ConfigurationManagementException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getDescription(), tenantDomain), e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
    }

    @Override
    public CORSConfiguration getCORSConfiguration(String tenantDomain) throws CORSManagementServiceException {

        CORSConfiguration cachedResult = getCORSConfigurationFromCache(tenantDomain);
        if (cachedResult != null) {
            return cachedResult;
        }

        try {
            FrameworkUtils.startTenantFlow(tenantDomain);

            Resource resource = getResource(CORS_CONFIGURATION_RESOURCE_TYPE_NAME, CORS_CONFIGURATION_RESOURCE_NAME);
            CORSConfiguration corsConfiguration;
            if (resource == null) {
                corsConfiguration = CORSConfigurationUtils.getServerCORSConfiguration();
                if (log.isDebugEnabled()) {
                    log.debug(String.format("CORS configuration not found for tenant %s. Using the server CORS " +
                            "configuration instead.", tenantDomain));
                }
            } else {
                corsConfiguration = new ResourceToCORSConfiguration().apply(resource);
            }

            // Add to cache.
            addCORSConfigurationToCache(corsConfiguration, tenantDomain);

            return corsConfiguration;
        } catch (ConfigurationManagementException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getDescription(), tenantDomain), e);
        } finally {
            FrameworkUtils.endTenantFlow();
        }
    }

    /**
     * Retrieve the ConfigurationManager instance from the CORSServiceHolder.
     *
     * @return ConfigurationManager The ConfigurationManager instance.
     */
    private ConfigurationManager getConfigurationManager() {

        return CORSServiceHolder.getInstance().getConfigurationManager();
    }

    /**
     * Returns the resources of a tenant with the given type.
     *
     * @param resourceTypeName Type of the resource to be retrieved.
     * @return Returns an instance of {@code Resources} with the resources of given type.
     * @throws ConfigurationManagementException
     */
    private Resources getResources(String resourceTypeName) throws ConfigurationManagementException {

        return getConfigurationManager().getResourcesByType(resourceTypeName);
    }

    /**
     * Configuration Management API returns a ConfigurationManagementException with the error code CONFIGM_00017 when
     * resource is not found. This method wraps the original method and returns null if the resource is not found.
     *
     * @param resourceTypeName Resource type name.
     * @param resourceName     Resource name.
     * @return Retrieved resource from the configuration store. Returns {@code null} if the resource is not found.
     * @throws ConfigurationManagementException
     */
    private Resource getResource(String resourceTypeName, String resourceName) throws ConfigurationManagementException {

        try {
            return getConfigurationManager().getResource(resourceTypeName, resourceName);
        } catch (ConfigurationManagementException e) {
            if (e.getErrorCode().equals(ERROR_CODE_RESOURCE_DOES_NOT_EXISTS.getCode())) {
                return null;
            } else {
                throw e;
            }
        }
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
