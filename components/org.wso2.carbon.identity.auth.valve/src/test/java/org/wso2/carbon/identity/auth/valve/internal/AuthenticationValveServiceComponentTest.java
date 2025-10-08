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
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;

import java.util.List;


public class AuthenticationValveServiceComponentTest {

    @Mock
    private ComponentContext componentContext;

    private AutoCloseable openMocks;

    @BeforeMethod
    public void setUp() {
        openMocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() {
        if (openMocks != null) {
            try {
                openMocks.close();
            } catch (Exception ignored) { }
        }
    }

    @Test
    public void testActivate() {
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.activate(componentContext);
    }

    @Test
    public void testAddAuthenticationRequestBuilderFactory() {
        AuthenticationRequestBuilderFactory authenticationRequestBuilderFactory = AuthenticationRequestBuilderFactory
                .getInstance();
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.addAuthenticationRequestBuilderFactory(authenticationRequestBuilderFactory);

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();

        List<AuthenticationRequestBuilderFactory> requestBuilderFactories = authenticationValveServiceHolder
                .getRequestBuilderFactories();
        if(requestBuilderFactories.isEmpty()){
            Assert.fail("AuthenticationRequestBuilderFactory list is empty.");
        }
        for (AuthenticationRequestBuilderFactory builderFactory : requestBuilderFactories) {
            Assert.assertEquals(authenticationRequestBuilderFactory, builderFactory);
        }
    }

    @Test
    public void testSetAuthenticationManager() {
        AuthenticationManager authenticationManager = AuthenticationManager.getInstance();
        AuthenticationValveServiceComponent authenticationValveServiceComponent = new
                AuthenticationValveServiceComponent();
        authenticationValveServiceComponent.setAuthenticationManager(authenticationManager);

        AuthenticationValveServiceHolder authenticationValveServiceHolder = AuthenticationValveServiceHolder
                .getInstance();

        List<AuthenticationManager> authenticationManagers = authenticationValveServiceHolder
                .getAuthenticationManagers();
        if(authenticationManagers.isEmpty()){
            Assert.fail("AuthenticationManager list is empty.");
        }
        for (AuthenticationManager manager : authenticationManagers) {
            Assert.assertEquals(authenticationManager, manager);
        }
    }
}
