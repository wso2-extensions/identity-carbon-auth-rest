/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.auth.service.util;

import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;

import java.util.HashMap;
import java.util.Map;

//import org.wso2.carbon.identity.core.util.IdentityConfigParser;
//import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

//import org.wso2.carbon.identity.core.util.IdentityConfigParser;
//import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

/**
 * Authentication Configuration Utilities
 *
 */
public class AuthConfigurationUtil {

    private static AuthConfigurationUtil authConfigurationUtil = new AuthConfigurationUtil();

    private Map<String, String> applicationConfigMap = new HashMap<>();

    private AuthConfigurationUtil() {
    }

    public static AuthConfigurationUtil getInstance() {
        return AuthConfigurationUtil.authConfigurationUtil;
    }


    /**
     * Build rest api resource control config.
     */
    public void buildResourceAccessControlData() {

        //        OMElement resourceAccessControl = IdentityConfigParser.getInstance().getConfigElement(Constants
        //                .RESOURCE_ACCESS_CONTROL_ELE);
        //        if ( resourceAccessControl != null ) {
        //
        //            Iterator<OMElement> resources = resourceAccessControl.getChildrenWithName(
        //                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.RESOURCE_ELE));
        //            if ( resources != null ) {
        //
        //                while ( resources.hasNext() ) {
        //                    OMElement resource = resources.next();
        //                    ResourceConfig resourceConfig = new ResourceConfig();
        //                    String httpMethod = resource.getAttributeValue(
        //                            new QName(Constants.RESOURCE_HTTP_METHOD_ATTR));
        //                    String context = resource.getAttributeValue(new QName(Constants.RESOURCE_CONTEXT_ATTR));
        //                    String isSecured = resource.getAttributeValue(new QName(Constants.RESOURCE_SECURED_ATTR));
        //   String isCrossTenantAllowed = resource.getAttributeValue(new QName(Constants.RESOURCE_CROSS_TENANT_ATTR));
        //
        //                    StringBuilder permissionBuilder = new StringBuilder();
        //                    Iterator<OMElement> permissionsIterator = resource.getChildrenWithName(
        //                            new QName(Constants.RESOURCE_PERMISSION_ELE));
        //                    if ( permissionsIterator != null ) {
        //                        while ( permissionsIterator.hasNext() ) {
        //                            OMElement permissionElement = permissionsIterator.next();
        //                            String permission = permissionElement.getText();
        //                            if ( StringUtils.isNotEmpty(permissionBuilder.toString()) &&
        //                                    StringUtils.isNotEmpty(permission) ) {
        //                                permissionBuilder.append(",");
        //                            }
        //                            if ( StringUtils.isNotEmpty(permission) ) {
        //                                permissionBuilder.append(permission);
        //                            }
        //                        }
        //                    }
        //
        //                    resourceConfig.setContext(context);
        //                    resourceConfig.setHttpMethod(httpMethod);
        //                    if ( StringUtils.isNotEmpty(isSecured) && (Boolean.TRUE.toString().equals(isSecured) ||
        //                            Boolean.FALSE.toString().equals(isSecured)) ) {
        //                        resourceConfig.setIsSecured(Boolean.parseBoolean(isSecured));
        //                    }
        //                    if (StringUtils.isNotEmpty(isCrossTenantAllowed) &&
        // (Boolean.TRUE.toString().equals(isCrossTenantAllowed) ||
        //                            Boolean.FALSE.toString().equals(isCrossTenantAllowed))) {
        //                        resourceConfig.setIsCrossTenantAllowed(Boolean.parseBoolean(isCrossTenantAllowed));
        //                    }
        //                    resourceConfig.setPermissions(permissionBuilder.toString());
        //                    resourceConfigMap.put(new ResourceConfigKey(context, httpMethod), resourceConfig);
        //                }
        //            }
        //        }
    }

    /**
     * Build rest api resource control config.
     */
    public void buildClientAuthenticationHandlerControlData() {

        //        OMElement resourceAccessControl = IdentityConfigParser.getInstance().getConfigElement(Constants
        //                .CLIENT_APP_AUTHENTICATION_ELE);
        //        if ( resourceAccessControl != null ) {
        //
        //            Iterator<OMElement> applications = resourceAccessControl.getChildrenWithName(
        //                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.APPLICATION_ELE));
        //            if ( applications != null ) {
        //                while ( applications.hasNext() ) {
        //                    OMElement resource = applications.next();
        //                    String appName = resource.getAttributeValue(new QName(Constants.APPLICATION_NAME_ATTR));
        //                    String hash = resource.getAttributeValue(new QName(Constants.APPLICATION_HASH_ATTR));
        //                    applicationConfigMap.put(appName, hash);
        //                }
        //            }
        //        }
    }

    public String getClientAuthenticationHash(String appName) {
        return applicationConfigMap.get(appName);
    }
}
