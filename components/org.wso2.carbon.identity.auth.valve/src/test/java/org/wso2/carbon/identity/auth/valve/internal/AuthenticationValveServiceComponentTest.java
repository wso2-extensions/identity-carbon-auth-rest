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
package org.wso2.carbon.identity.auth.valve.internal;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.osgi.service.component.ComponentContext;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;

import java.util.List;


public class AuthenticationValveServiceComponentTest extends PowerMockTestCase {

    @Mock
    private ComponentContext componentContext;
    @Mock
    private AuthenticationValveServiceHolder authenticationValveServiceHolder;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testActivate() throws Exception {
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.activate(componentContext);
    }

    @Test
    public void testAddAuthenticationRequestBuilderFactory() throws Exception {
        AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = AuthenticationRequestBuilderFactory
                .getInstance();
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.addAuthenticationRequestBuilderFactory(authenticationRequestBuilderFactory);

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();

        List<AuthenticationRequestBuilderFactory> requestBuilderFactories = authenticationValveServiceHolder
                .getRequestBuilderFactories();
        for (AuthenticationRequestBuilderFactory builderFactory : requestBuilderFactories) {
            Assert.assertEquals(authenticationRequestBuilderFactory, builderFactory);
        }
    }

    @Test
    public void testSetAuthenticationManager() throws Exception {
        AuthenticationManager authenticationManager = AuthenticationManager.getInstance();
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.setAuthenticationManager(authenticationManager);

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();

        List<AuthenticationManager> authenticationManagers = authenticationValveServiceHolder
                .getAuthenticationManagers();
        for (AuthenticationManager manager : authenticationManagers) {
            Assert.assertEquals(authenticationManager, manager);
        }
    }
}