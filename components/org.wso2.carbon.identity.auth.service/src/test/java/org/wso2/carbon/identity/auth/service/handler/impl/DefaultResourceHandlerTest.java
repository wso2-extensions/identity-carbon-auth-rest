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

import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.common.base.handler.InitConfig;

import static org.testng.Assert.*;

/**
 * Tests for the DefaultResourceHandler
 */
public class DefaultResourceHandlerTest {

    private DefaultResourceHandler defaultResourceHandler = new DefaultResourceHandler();

    @Test
    public void testGetSecuredResource() throws Exception {
        defaultResourceHandler.init(new InitConfig());
        assertNull(defaultResourceHandler.getSecuredResource(new ResourceConfigKey("foo", "get")));
        assertNotNull(defaultResourceHandler.getSecuredResource(
                new ResourceConfigKey("(.*)/api/identity/user/(.*)", "all")));
    }

    @Test
    public void testInit() throws Exception {
        defaultResourceHandler.init(null);
    }

    @Test
    public void testGetName() throws Exception {
        assertEquals(defaultResourceHandler.getName(), "DefaultResourceHandler");
    }

    @Test
    public void testIsEnabled() throws Exception {
        assertTrue(defaultResourceHandler.isEnabled());
    }

    @Test
    public void testGetPriority() throws Exception {
        assertTrue(defaultResourceHandler.getPriority() > 0);
    }

}