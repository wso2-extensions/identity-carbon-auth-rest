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

import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.core.handler.IdentityHandler;
import org.wso2.carbon.identity.core.handler.InitConfig;

/**
 * ResourceHandler can be extended to handle resource permission and will execute all the handlers until it gets the
 * permission strings.
 */
public abstract class ResourceHandler implements IdentityHandler {

    private static final String HTTP_ALL_METHOD = "all";

    /**
     * Handle Resource.
     *
     * @param authorizationContext
     * @return
     */
    public abstract boolean handleResource(AuthorizationContext authorizationContext);

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
