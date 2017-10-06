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
package org.wso2.carbon.identity.auth.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;
import org.wso2.carbon.identity.auth.valve.util.AuthHandlerManager;

public class AuthHandlerManagerTest extends PowerMockTestCase {

    @Mock
    private Request request;
    @Mock
    private Response response;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testGetAuthenticationManager() throws Exception {

        AuthenticationManager authenticationManager = AuthenticationManager.getInstance();

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();
        authenticationValveServiceHolder.getAuthenticationManagers().add(authenticationManager);
        AuthHandlerManager authHandlerManager = AuthHandlerManager.getInstance();
        AuthenticationManager authenticationManagerReturn = authHandlerManager.getAuthenticationManager();

        Assert.assertEquals(authenticationManager, authenticationManagerReturn);
    }

    @Test
    public void testGetInstance() throws Exception {
        AuthHandlerManager authHandlerManager = AuthHandlerManager.getInstance();
        Assert.assertNotNull(authHandlerManager);
    }

    @Test
    public void testGetRequestBuilder() throws Exception {
        AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = AuthenticationRequestBuilderFactory
                .getInstance();

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();
        authenticationValveServiceHolder.getRequestBuilderFactories().add(authenticationRequestBuilderFactory);
        AuthHandlerManager authHandlerManager = AuthHandlerManager.getInstance();
        AuthenticationRequestBuilderFactory requestBuilderFactoryReturn = authHandlerManager.getRequestBuilder(request,
                                                                                                               response);
        Assert.assertEquals(authenticationRequestBuilderFactory, requestBuilderFactoryReturn);
    }
}