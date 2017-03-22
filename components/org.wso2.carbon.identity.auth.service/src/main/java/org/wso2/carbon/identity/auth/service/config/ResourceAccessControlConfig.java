/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.auth.service.config;

import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Config bean for resource access control.
 * Holds the configuration from the deployment config file.
 * Holds default configurations.
 */
public class ResourceAccessControlConfig {

    private Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = new HashMap<>();

    public ResourceAccessControlConfig() {
        initDefaultValues();
    }

    /**
     * Returns the security resource configuration given the resource url pattern and the method.
     * @param resourceConfigKey The key to identify the resource.
     * @return ResourceConfig if found.
     */
    public ResourceConfig getSecuredConfig(ResourceConfigKey resourceConfigKey) {
        return resourceConfigMap.entrySet().stream().filter(c -> c.getKey().equals(resourceConfigKey))
                .map(e -> e.getValue()).findAny().orElse(null);
    }

    /**
     * Initialize with the following XML structure.
     * <code>
     *     <ResourceAccessControl>
     <Resource context="(.*)/api/identity/user/(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/api/identity/recovery/(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/.well-known(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/identity/register(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/delete</Permissions>
     </Resource>
     <Resource context="(.*)/identity/connect/register(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/create</Permissions>
     </Resource>
     <Resource context="(.*)/oauth2/introspect(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/view</Permissions>
     </Resource>
     <Resource context="(.*)/api/identity/entitlement/(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/pep</Permissions>
     </Resource>
     </ResourceAccessControl>
     * </code>
     */
    private void initDefaultValues() {
        withResource("(.*)/api/identity/user/(.*)", true, "all").add();
        withResource("(.*)/api/identity/recovery/(.*)", true, "all").add();
        withResource("(.*)/.well-known(.*)", true, "all").add();
        withResource("(.*)/identity/register(.*)", true, "all")
                .withPermission("/permission/admin/manage/identity/applicationmgt/delete").add();
        withResource("(.*)/identity/connect/register(.*)", true, "all")
                .withPermission("/permission/admin/manage/identity/applicationmgt/create").add();
        withResource("(.*)/oauth2/introspect(.*)", true, "all")
                .withPermission("/permission/admin/manage/identity/applicationmgt/view").add();
        withResource("(.*)/api/identity/entitlement/(.*)", true, "all")
                .withPermission("/permission/admin/manage/identity/pep").add();


        /* These are for SCIM endpoints, and will be moved to config on later kernels */
        withResource("(.*)/scim/v2/Me", true, "GET").add();
        withResource("(.*)/scim/v2/ServiceProviderConfig", true, "all")
                .add();
        withResource("(.*)/scim/v2/ResourceType", true, "all")
                .add();
        withResource("(.*)/scim/v2/(.*)", true, "all")
                .withPermission("/permission/admin/manage").add();
    }

    private ResourceBuilder withResource(String context, boolean isSecured, String httpMethod) {
        ResourceConfig resourceConfig = new ResourceConfig();
        resourceConfig.setContext(context);
        resourceConfig.setIsSecured(isSecured);
        resourceConfig.setHttpMethod(httpMethod);

        return new ResourceBuilder(resourceConfig);
    }

    /**
     * Internal builder for convenience.
     */
    private class ResourceBuilder {

        private ResourceConfig resourceConfig;
        private List<String> permissionsList = new ArrayList<>();

        private ResourceBuilder(ResourceConfig resourceConfig) {
            this.resourceConfig = resourceConfig;
        }

        ResourceBuilder withPermission(String permission) {
            permissionsList.add(permission);
            return this;
        }

        void add() {
            ResourceConfigKey key = ResourceConfigKey.generateKey(resourceConfig);
            resourceConfigMap.put(key, resourceConfig);
        }
    }
}
