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
package org.wso2.carbon.identity.authz.service.handler;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.model.ResourceAccessControlConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ResourceHandler implements IdentityHandler{


    public boolean handleResource(AuthorizationContext authorizationContext){
        boolean isResourcePermissionFound = false ;
        List<String> permissions = new ArrayList<>();
        Map<ResourceAccessControlConfig.ResourceKey, ResourceAccessControlConfig> resourceAccessControlConfigHolder =
                IdentityUtil.getResourceAccessControlConfigHolder();
        StringBuilder permissionsBuilder = new StringBuilder();
        for (Map.Entry<ResourceAccessControlConfig.ResourceKey, ResourceAccessControlConfig> entry : resourceAccessControlConfigHolder.entrySet())
        {
            ResourceAccessControlConfig resourceAccessControlConfig = entry.getValue();
            if(resourceAccessControlConfig.getContext().endsWith("*")){
                if(resourceAccessControlConfig.getContext().startsWith(authorizationContext.getContext())
                        && authorizationContext.getHttpMethods().contains(resourceAccessControlConfig.getHttpMethod())){
                    if(StringUtils.isNotEmpty(permissionsBuilder.toString()) && StringUtils.isNotEmpty(resourceAccessControlConfig.getPermissions())){
                        permissionsBuilder.append(",");
                    }
                    permissionsBuilder.append(resourceAccessControlConfig.getPermissions());
                }
            }else{
                if(resourceAccessControlConfig.getContext().equals(authorizationContext.getContext())
                        && authorizationContext.getHttpMethods().contains(resourceAccessControlConfig.getHttpMethod())){
                    if(StringUtils.isNotEmpty(permissionsBuilder.toString()) && StringUtils.isNotEmpty(resourceAccessControlConfig.getPermissions())){
                        permissionsBuilder.append(",");
                    }
                    permissionsBuilder.append(resourceAccessControlConfig.getPermissions());

                }
            }
        }
        if(StringUtils.isNotEmpty(permissionsBuilder.toString())){
            isResourcePermissionFound = true ;
        }
        authorizationContext.setPermissionString(permissionsBuilder.toString());
        return isResourcePermissionFound ;
    }


    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 0;
    }
}
