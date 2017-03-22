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

package org.wso2.carbon.identity.auth.rest.test;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.common.base.handler.InitConfig;
import org.wso2.carbon.identity.mgt.RealmService;

import java.util.HashMap;
import java.util.Map;

/**
 * Tests Service component having a service and resource handler.
 */
@Component(
        name = "org.wso2.carbon.identity.auth.rest.test",
        immediate = true,
        property = { "componentName=wso2-carbon-identity-rest-auth-test" })
public class RestAuthTestServicesComponent {

    @Activate
    protected void activate(BundleContext bundleContext) {
        bundleContext.registerService(RealmService.class, () -> new MockIdentityStore(), null);

        ResourceHandler resourceHandler = new TestResourceHandler();
        resourceHandler.init(null);
        bundleContext.registerService(ResourceHandler.class, resourceHandler, null);
    }

    private static class TestResourceHandler extends ResourceHandler {

        private Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = new HashMap<>();

        @Override
        public ResourceConfig getSecuredResource(ResourceConfigKey resourceConfigKey) {
            return resourceConfigMap.entrySet().stream().filter(c -> c.getKey().equals(resourceConfigKey))
                    .map(e -> e.getValue()).findAny().orElse(null);
        }

        @Override
        public void init(InitConfig initConfig) {
            ResourceConfig resourceConfig = new ResourceConfig();
            resourceConfig.setHttpMethod("all");
            resourceConfig.setIsSecured(true);
            resourceConfig.setContext("(.*)/simple-rest/test/hello/(.*)");
            ResourceConfigKey key = ResourceConfigKey.generateKey(resourceConfig);

            resourceConfigMap.put(key, resourceConfig);

            ResourceConfig resourceConfig2 = new ResourceConfig();
            resourceConfig2.setHttpMethod("all");
            resourceConfig2.setIsSecured(false);
            resourceConfig2.setContext("(.*)/simple-rest/test/public/hello/(.*)");
            ResourceConfigKey key2 = ResourceConfigKey.generateKey(resourceConfig2);

            resourceConfigMap.put(key2, resourceConfig2);
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        public boolean isEnabled() {
            return false;
        }

        @Override
        public int getPriority() {
            return 1;
        }
    }
}
