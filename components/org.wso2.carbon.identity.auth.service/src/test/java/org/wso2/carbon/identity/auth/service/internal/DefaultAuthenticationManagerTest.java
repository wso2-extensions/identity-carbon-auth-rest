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

package org.wso2.carbon.identity.auth.service.internal;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.BasicAuthenticationHandler;
import org.wso2.carbon.identity.auth.service.handler.impl.DefaultResourceHandler;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;

import static org.testng.Assert.*;

public class DefaultAuthenticationManagerTest {

    private DefaultAuthenticationManager authenticationManager;

    @BeforeTest
    protected void setUp() {
        authenticationManager = new DefaultAuthenticationManager();
    }

    @Test
    public void testGetSecuredResource() throws Exception {
        ResourceConfig resourceConfig = authenticationManager.getSecuredResource(new ResourceConfigKey("foo", "bar"));
        assertNull(resourceConfig, "Null should return for resource Mapping not configured");

        DefaultResourceHandler resourceHandler = new DefaultResourceHandler();
        resourceHandler.init(null);
        authenticationManager.addResourceHandler(resourceHandler);

        ResourceConfig resourceConfig2 = authenticationManager
                .getSecuredResource(new ResourceConfigKey("foo/api/identity/user/test", "GET"));
        assertNotNull(resourceConfig2);
    }

    @Test
    public void testRemoveAuthenticationHandler()
            throws AuthServerException, AuthenticationFailException, AuthClientException {
        BasicAuthenticationHandler basicAuthenticationHandler = new BasicAuthenticationHandler();
        authenticationManager.addAuthenticationHandler(basicAuthenticationHandler);
        authenticationManager.removeAuthenticationHandler(basicAuthenticationHandler);

        AuthenticationRequest.AuthenticationRequestBuilder builder =
                new AuthenticationRequest.AuthenticationRequestBuilder();
        AuthenticationContext authenticationContext = new AuthenticationContext(builder.build());

        AuthenticationResult result = authenticationManager.authenticate(authenticationContext);
        assertEquals(result.getAuthenticationStatus(), AuthenticationStatus.FAILED);

        builder.setMethod("GET");
        builder.setContextPath("foo/api/identity/user/test/foo/bar");
        authenticationContext = new AuthenticationContext(builder.build());
        try {
            authenticationManager.authenticate(authenticationContext);
            fail("There should be exception when no handler found");
        } catch (AuthRuntimeException ae) {
            assertTrue(true);
        }
    }

    @Test
    public void testGetFirstPriorityHandler_WithAnyHandler() {
        BasicAuthenticationHandler basicAuthenticationHandler = new BasicAuthenticationHandler();
        authenticationManager.addAuthenticationHandler(basicAuthenticationHandler);

        AuthenticationRequest.AuthenticationRequestBuilder builder =
                new AuthenticationRequest.AuthenticationRequestBuilder();
        AuthenticationContext authenticationContext = new AuthenticationContext(builder.build());
        AuthenticationHandler handler =
                authenticationManager.getFirstPriorityAuthenticationHandler(false, authenticationContext);

        assertEquals(handler, basicAuthenticationHandler);
    }
}