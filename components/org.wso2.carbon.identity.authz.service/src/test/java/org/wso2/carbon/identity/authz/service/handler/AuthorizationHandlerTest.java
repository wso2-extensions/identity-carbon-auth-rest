/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Unit tests for AuthorizationHandler class, specifically for the authorizeUser method.
 */
public class AuthorizationHandlerTest {

    private AuthorizationHandler authorizationHandler;

    @BeforeClass
    public void setUp() {

        authorizationHandler = new AuthorizationHandler();
    }

    @DataProvider
    public Object[][] authorizeUserTestData() {

        return new Object[][]{
                // Test case 1: Required scopes fully granted
                {
                        Arrays.asList("read", "write"),              // requiredScopes
                        null,                                        // operationScopeMap
                        Arrays.asList("read", "write", "admin"),     // allowedScopes
                        AuthorizationStatus.GRANT,                  // expectedStatus
                        false                                        // expectedOperationScopeAuthRequired
                },
                // Test case 2: Required scopes partially granted, no operation scopes
                {
                        Arrays.asList("read", "write", "delete"),    // requiredScopes
                        null,                                        // operationScopeMap
                        Arrays.asList("read", "write"),              // allowedScopes
                        AuthorizationStatus.DENY,                   // expectedStatus
                        true                                         // expectedOperationScopeAuthRequired
                },
                // Test case 3: Required scopes not granted, but operation scope granted
                {
                        Arrays.asList("admin", "superuser"),        // requiredScopes
                        createOperationScopeMap("manage"),          // operationScopeMap
                        Arrays.asList("read", "write", "manage"),    // allowedScopes
                        AuthorizationStatus.GRANT,                  // expectedStatus
                        true
                        // expectedOperationScopeAuthRequired (overridden by line 163)
                },
                // Test case 4: Neither required scopes nor operation scopes granted
                {
                        Arrays.asList("admin", "superuser"),        // requiredScopes
                        createOperationScopeMap("delete"),          // operationScopeMap
                        Arrays.asList("read", "write"),              // allowedScopes
                        AuthorizationStatus.DENY,                   // expectedStatus
                        true                                         // expectedOperationScopeAuthRequired
                },
                // Test case 5: Empty required scopes, no operation scopes
                {
                        Collections.emptyList(),                    // requiredScopes
                        null,                                        // operationScopeMap
                        Arrays.asList("read", "write"),              // allowedScopes
                        AuthorizationStatus.GRANT,                  // expectedStatus
                        false                                        // expectedOperationScopeAuthRequired
                },
                // Test case 6: Empty allowed scopes
                {
                        Arrays.asList("read", "write"),              // requiredScopes
                        null,                                        // operationScopeMap
                        Collections.emptyList(),                    // allowedScopes
                        AuthorizationStatus.DENY,                   // expectedStatus
                        true                                         // expectedOperationScopeAuthRequired
                },
                // Test case 7: Required scopes not granted, operation scope map empty
                {
                        Arrays.asList("admin"),                      // requiredScopes
                        Collections.emptyMap(),                     // operationScopeMap
                        Arrays.asList("read", "write"),              // allowedScopes
                        AuthorizationStatus.DENY,                   // expectedStatus
                        true                                         // expectedOperationScopeAuthRequired
                },
                // Test case 8: Required scopes not granted, multiple operation scopes, one granted
                {
                        Arrays.asList("admin"),                      // requiredScopes
                        createMultipleOperationScopeMap(),          // operationScopeMap
                        Arrays.asList("read", "write", "manage"),    // allowedScopes
                        AuthorizationStatus.GRANT,                  // expectedStatus
                        true
                        // expectedOperationScopeAuthRequired (overridden by line 163)
                },
                // Test case 9: Required scopes not granted, multiple operation scopes, none granted
                {
                        Arrays.asList("admin"),                      // requiredScopes
                        createMultipleOperationScopeMap(),          // operationScopeMap
                        Arrays.asList("read", "write"),              // allowedScopes
                        AuthorizationStatus.DENY,                   // expectedStatus
                        true                                         // expectedOperationScopeAuthRequired
                },
                // Test case 10: Single required scope granted exactly
                {
                        Arrays.asList("read"),                       // requiredScopes
                        null,                                        // operationScopeMap
                        Arrays.asList("read"),                       // allowedScopes
                        AuthorizationStatus.GRANT,                  // expectedStatus
                        false                                        // expectedOperationScopeAuthRequired
                }
        };
    }

    @Test(dataProvider = "authorizeUserTestData")
    public void testAuthorizeUser(List<String> requiredScopes,
                                  Map<String, String> operationScopeMap,
                                  List<String> allowedScopes,
                                  AuthorizationStatus expectedStatus,
                                  boolean expectedOperationScopeAuthRequired) throws Exception {

        // Create AuthorizationResult with initial DENY status
        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);

        // Use reflection to access the private authorizeUser method
        Method authorizeUserMethod = AuthorizationHandler.class.getDeclaredMethod(
                "authorizeUser",
                List.class,
                Map.class,
                AuthorizationResult.class,
                List.class
                                                                                 );
        authorizeUserMethod.setAccessible(true);

        // Invoke the method
        authorizeUserMethod.invoke(authorizationHandler, requiredScopes, operationScopeMap,
                authorizationResult, allowedScopes);

        // Verify the results
        Assert.assertEquals(authorizationResult.getAuthorizationStatus(), expectedStatus,
                "Authorization status should match expected value");
        Assert.assertEquals(authorizationResult.isOperationScopeAuthorizationRequired(),
                expectedOperationScopeAuthRequired,
                "Operation scope authorization required flag should match expected value");
    }

    @Test
    public void testAuthorizeUserWithNullRequiredScopes() throws Exception {

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        List<String> allowedScopes = Arrays.asList("read", "write");

        Method authorizeUserMethod = AuthorizationHandler.class.getDeclaredMethod(
                "authorizeUser",
                List.class,
                Map.class,
                AuthorizationResult.class,
                List.class
                                                                                 );
        authorizeUserMethod.setAccessible(true);

        // This should throw a NullPointerException because containsAll is called on null
        try {
            authorizeUserMethod.invoke(authorizationHandler, null, null, authorizationResult, allowedScopes);
            Assert.fail("Expected NullPointerException when requiredScopes is null");
        } catch (Exception e) {
            Assert.assertTrue(e.getCause() instanceof NullPointerException,
                    "Should throw NullPointerException for null requiredScopes");
        }
    }

    @Test
    public void testAuthorizeUserWithNullAllowedScopes() throws Exception {

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        List<String> requiredScopes = Arrays.asList("read", "write");

        Method authorizeUserMethod = AuthorizationHandler.class.getDeclaredMethod(
                "authorizeUser",
                List.class,
                Map.class,
                AuthorizationResult.class,
                List.class
                                                                                 );
        authorizeUserMethod.setAccessible(true);

        // This should throw a NullPointerException because HashSet constructor is called with null
        try {
            authorizeUserMethod.invoke(authorizationHandler, requiredScopes, null, authorizationResult, null);
            Assert.fail("Expected NullPointerException when allowedScopes is null");
        } catch (Exception e) {
            Assert.assertTrue(e.getCause() instanceof NullPointerException,
                    "Should throw NullPointerException for null allowedScopes");
        }
    }

    @Test
    public void testAuthorizeUserRequiredScopesTakePrecedence() throws Exception {

        AuthorizationResult authorizationResult = new AuthorizationResult(AuthorizationStatus.DENY);
        List<String> requiredScopes = Arrays.asList("read", "write");
        Map<String, String> operationScopeMap = new HashMap<>();
        operationScopeMap.put("operation1", "manage");
        List<String> allowedScopes = Arrays.asList("read", "write", "manage");

        Method authorizeUserMethod = AuthorizationHandler.class.getDeclaredMethod(
                "authorizeUser",
                List.class,
                Map.class,
                AuthorizationResult.class,
                List.class
                                                                                 );
        authorizeUserMethod.setAccessible(true);

        authorizeUserMethod.invoke(authorizationHandler, requiredScopes, operationScopeMap,
                authorizationResult, allowedScopes);

        // Required scopes are satisfied, so operation scope check should be skipped
        Assert.assertEquals(authorizationResult.getAuthorizationStatus(), AuthorizationStatus.GRANT);
        Assert.assertFalse(authorizationResult.isOperationScopeAuthorizationRequired());
    }

    // Helper methods to create test data
    private static Map<String, String> createOperationScopeMap(String scope) {

        Map<String, String> operationScopeMap = new HashMap<>();
        operationScopeMap.put("operation1", scope);
        return operationScopeMap;
    }

    private static Map<String, String> createMultipleOperationScopeMap() {

        Map<String, String> operationScopeMap = new HashMap<>();
        operationScopeMap.put("operation1", "delete");
        operationScopeMap.put("operation2", "manage");
        operationScopeMap.put("operation3", "admin");
        return operationScopeMap;
    }
}
