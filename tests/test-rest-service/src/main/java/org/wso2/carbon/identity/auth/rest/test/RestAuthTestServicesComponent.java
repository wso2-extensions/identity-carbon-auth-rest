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

@Component(
        name = "org.wso2.carbon.identity.auth.rest.test",
        immediate = true,
        property = { "componentName=wso2-carbon-identity-rest-auth-test" })
public class RestAuthTestServicesComponent {

    @Activate
    protected void activate(BundleContext bundleContext) {
        bundleContext.registerService(RealmService.class, () -> new MockIdentityStore(), null);

        ResourceHandler resourceHandler = new TestResourceHandler();
        bundleContext.registerService(ResourceHandler.class, resourceHandler, null);
    }

    private static class TestResourceHandler extends ResourceHandler {

        @Override
        public ResourceConfig getSecuredResource(ResourceConfigKey resourceConfigKey) {
            ResourceConfig resourceConfig = new ResourceConfig();
            resourceConfig.setHttpMethod("all");
            resourceConfig.setIsSecured(false);
            resourceConfig.setContext("(.*)/simple-rest/test/hello/(.*)");
            return resourceConfig;
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
            return false;
        }

        @Override
        public int getPriority() {
            return 1;
        }
    }
}
