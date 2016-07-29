/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.auth.service.handler;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.model.ResourceAccessControlConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.Map;

/**
 * ResourceHandler can be extended to handle resource context and will execute all the handlers.
 *
 */
public class ResourceHandler implements IdentityHandler {

    private static final String HTTP_ALL_METHOD = "all";

    /**
     * Handle Resource.
     *
     * @param authenticationContext
     * @return
     */
    public boolean handleResource(AuthenticationContext authenticationContext) {

        boolean isSecuredResourceFound = false;
        Map<ResourceAccessControlConfig.ResourceKey, ResourceAccessControlConfig> resourceAccessControlConfigHolder =
                IdentityUtil.getResourceAccessControlConfigHolder();
        for (Map.Entry<ResourceAccessControlConfig.ResourceKey, ResourceAccessControlConfig> entry :
                                                                        resourceAccessControlConfigHolder.entrySet()) {
            ResourceAccessControlConfig resourceAccessControlConfig = entry.getValue();
            String configuredContext = resourceAccessControlConfig.getContext();
            String httpMethods = resourceAccessControlConfig.getHttpMethod();

            if ((configuredContext.endsWith("*") && authenticationContext.getAuthenticationRequest().getContextPath().startsWith(configuredContext.substring(0, configuredContext.length() - 1)) ) ||
                    configuredContext.equals(authenticationContext.getAuthenticationRequest().getContextPath())) {
                if (authenticationContext.getAuthenticationRequest().getMethod().contains(httpMethods) || HTTP_ALL_METHOD.equals(httpMethods)
                        || StringUtils.isNotEmpty(httpMethods)) {
                    if(resourceAccessControlConfig.isSecured()) {
                        isSecuredResourceFound = true;
                    }
                }
            }
        }
        return isSecuredResourceFound;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "ResourceHandler";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 100;
    }
}
