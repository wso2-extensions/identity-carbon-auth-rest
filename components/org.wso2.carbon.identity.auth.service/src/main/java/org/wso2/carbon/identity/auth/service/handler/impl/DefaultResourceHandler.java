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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.wso2.carbon.identity.auth.service.config.ResourceAccessControlConfig;
import org.wso2.carbon.identity.auth.service.handler.ResourceHandler;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.common.base.handler.InitConfig;

/**
 * The default Resource handler provided by this component.
 * The configurations are read from the server config.
 */
public class DefaultResourceHandler extends ResourceHandler {

    private ResourceAccessControlConfig resourceAccessControlConfig;

    @Override
    public ResourceConfig getSecuredResource(ResourceConfigKey resourceConfigKey) {
        return resourceAccessControlConfig.getSecuredConfig(resourceConfigKey);
    }

    @Override
    public void init(InitConfig initConfig) {
        resourceAccessControlConfig = new ResourceAccessControlConfig();
    }

    @Override
    public String getName() {
        return "DefaultResourceHandler";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public int getPriority() {
        return 10;
    }
}
