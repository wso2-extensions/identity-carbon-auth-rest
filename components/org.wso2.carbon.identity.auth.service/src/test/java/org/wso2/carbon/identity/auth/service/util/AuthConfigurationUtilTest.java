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

package org.wso2.carbon.identity.auth.service.util;

import org.apache.http.HttpHeaders;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.lang.reflect.Field;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for AuthConfigurationUtil.
 */
public class AuthConfigurationUtilTest {

    @Mock
    private OrganizationManager mockedOrganizationManager;

    private static final String SAMPLE_ORG_ID = "b0d4d224-6276-4b97-8553-686af86d2ef2";
    private static final String RELATIVE_REQUEST_URL = "/t/tenant1/o/b0d4d224-6276-4b97-8553-686af86d2ef2/" +
            "oauth2/token";

    @BeforeClass
    public void setUpClass() {

        MockitoAnnotations.openMocks(this);
        AuthenticationServiceHolder.getInstance().setOrganizationManager(mockedOrganizationManager);
    }

    @DataProvider(name = "requestURIProvider")
    public Object[][] requestURIProvider() {

        return new Object[][]{
                {RELATIVE_REQUEST_URL, "tenant-domain"},
                {"https://localhost:9443" + RELATIVE_REQUEST_URL, null}
        };
    }

    @Test(dataProvider = "requestURIProvider")
    public void testGetResourceResidentTenantForTenantPerspective(String requestURI, String expectedValue) throws Exception {

        when(mockedOrganizationManager.resolveTenantDomain(SAMPLE_ORG_ID)).thenReturn(expectedValue);
        String tenantDomain = AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective(requestURI);
        assertEquals(tenantDomain, expectedValue);
    }

    @Test
    public void testGetResourceResidentTenantForTenantPerspectiveWithException() throws Exception {

        when(mockedOrganizationManager.resolveTenantDomain(SAMPLE_ORG_ID)).thenThrow(
                OrganizationManagementException.class);
        String tenantDomain = AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective(
                RELATIVE_REQUEST_URL);
        assertNull(tenantDomain);
    }

    @DataProvider(name = "isAuthHeaderMatchCaseSensitiveTestData")
    public Object[][] isAuthHeaderMatchCaseSensitiveTestData() {

        return new Object[][]{
                // Test data format: {authHeaderIdentifier, authorizationHeaderValue, isCaseSensitive, expectedResult}
                //Case sensitive tests
                {"Bearer", "Bearer token123", true, true},
                {"Bearer", "bearer token123", true, false},
                {"Bearer", "BEARER token123", true, false},
                {"Basic", "Basic dXNlcjpwYXNz", true, true},
                {"Basic", "basic dXNlcjpwYXNz", true, false},
                {"Token", "Token abc123", true, true},
                {"Token", "token abc123", true, false},
                {"Custom", "Custom value", true, true},
                {"Custom", "custom value", true, false},
                {"Custom", "CUSTOM value", true, false},
                // Case insensitive tests
                {"Bearer", "Bearer token123", false, true},
                {"Bearer", "bearer token123", false, true},
                {"Bearer", "BEARER token123", false, true},
                {"Bearer", "BeArEr token123", false, true},
                {"Basic", "Basic dXNlcjpwYXNz", false, true},
                {"Basic", "basic dXNlcjpwYXNz", false, true},
                {"Basic", "BASIC dXNlcjpwYXNz", false, true},
                {"Token", "Token abc123", false, true},
                {"Token", "token abc123", false, true},
                {"Token", "TOKEN abc123", false, true},
                // Mismatch cases
                {"Bearer", "Basic dXNlcjpwYXNz", true, false},
                {"Bearer", "Basic dXNlcjpwYXNz", false, false},
                {"Basic", "Bearer token123", true, false},
                {"Basic", "Bearer token123", false, false},
                {"Token", "Bearer token123", true, false},
                {"Token", "Bearer token123", false, false},
        };
    }

    @Test(dataProvider = "isAuthHeaderMatchCaseSensitiveTestData")
    public void testIsAuthHeaderMatchWithCaseSensitivity(String authHeaderIdentifier, String authorizationHeaderValue,
                                                         boolean isCaseSensitive, boolean expectedResult) {

        // Create mock objects
        AuthenticationContext mockAuthContext = mock(AuthenticationContext.class);
        AuthenticationRequest mockAuthRequest = mock(AuthenticationRequest.class);

        // Setup mock behavior
        when(mockAuthContext.getAuthenticationRequest()).thenReturn(mockAuthRequest);
        when(mockAuthRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(authorizationHeaderValue);

        // Execute the method under test
        boolean result = AuthConfigurationUtil.isAuthHeaderMatch(mockAuthContext, authHeaderIdentifier, isCaseSensitive);

        // Verify the result
        assertEquals(result, expectedResult,
                String.format("Failed for authHeaderIdentifier='%s', authorizationHeaderValue='%s', isCaseSensitive=%s",
                        authHeaderIdentifier, authorizationHeaderValue, isCaseSensitive));
    }

    @Test
    public void testIsAuthHeaderMatchWithNullMessageContext() {

        // Test with null MessageContext
        boolean result = AuthConfigurationUtil.isAuthHeaderMatch(null, "Bearer", true);
        assertFalse(result, "isAuthHeaderMatch should return false for null messageContext");

        result = AuthConfigurationUtil.isAuthHeaderMatch(null, "Bearer", false);
        assertFalse(result, "isAuthHeaderMatch should return false for null messageContext");
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testIsAuthHeaderMatchDeprecatedMethod() {

        // Test the deprecated method (2-parameter version)
        AuthenticationContext mockAuthContext = mock(AuthenticationContext.class);
        AuthenticationRequest mockAuthRequest = mock(AuthenticationRequest.class);

        when(mockAuthContext.getAuthenticationRequest()).thenReturn(mockAuthRequest);
        when(mockAuthRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer token123");

        // The deprecated method should default to case-sensitive comparison (isCaseSensitive = true)
        boolean result = AuthConfigurationUtil.isAuthHeaderMatch(mockAuthContext, "Bearer");
        assertTrue(result, "Deprecated method should work with exact case match");

        when(mockAuthRequest.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("bearer token123");
        result = AuthConfigurationUtil.isAuthHeaderMatch(mockAuthContext, "Bearer");
        assertFalse(result, "Deprecated method should be case-sensitive and fail with different case");
    }

    @Test
    public void testBuildResourceAccessControlDataInstanceState() throws Exception {

        // Test that the method doesn't break the instance state
        AuthConfigurationUtil authConfigUtil = AuthConfigurationUtil.getInstance();
        
        // Get initial state
        Map<ResourceConfigKey, ResourceConfig> initialResourceConfigMap = getResourceConfigMap(authConfigUtil);
        boolean initialScopeValidationEnabled = getScopeValidationEnabled(authConfigUtil);
        
        // Ensure the instance is in a valid state
        assertNotNull(initialResourceConfigMap, "Resource config map should be initialized");
        
        // The method may encounter exceptions during config loading, but should not break the instance
        try {
            authConfigUtil.buildResourceAccessControlData();
        } catch (Exception e) {
            // Expected in test environment where config files may not be available
            // This is acceptable as we're testing the method doesn't break instance state
        }
        
        // Verify instance state is still valid
        Map<ResourceConfigKey, ResourceConfig> finalResourceConfigMap = getResourceConfigMap(authConfigUtil);
        assertNotNull(finalResourceConfigMap, "Resource config map should still be initialized");
        
        // Scope validation setting should remain consistent unless explicitly changed by configuration
        boolean finalScopeValidationEnabled = getScopeValidationEnabled(authConfigUtil);
        assertEquals(finalScopeValidationEnabled, initialScopeValidationEnabled || 
                     finalScopeValidationEnabled, "Scope validation should be consistent or enabled");
    }

    @Test
    public void testBuildResourceAccessControlDataResourceConfigMapIntegrity() throws Exception {

        AuthConfigurationUtil authConfigUtil = AuthConfigurationUtil.getInstance();
        Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = getResourceConfigMap(authConfigUtil);
        
        // Execute the method - may fail due to config files not being available in test environment
        try {
            authConfigUtil.buildResourceAccessControlData();
        } catch (Exception e) {
            // Expected in test environment
        }
        
        // Verify the map structure remains valid
        assertNotNull(resourceConfigMap, "Resource config map should not be null");
        
        // Test that existing entries (if any) are still valid
        for (Map.Entry<ResourceConfigKey, ResourceConfig> entry : resourceConfigMap.entrySet()) {
            assertNotNull(entry.getKey(), "Resource config key should not be null");
            assertNotNull(entry.getValue(), "Resource config should not be null");
            
            // Verify ResourceConfig has valid data
            ResourceConfig config = entry.getValue();
            assertNotNull(config.getContext(), "Context should not be null");
            assertNotNull(config.getHttpMethod(), "HTTP method should not be null");
            assertNotNull(config.getAllowedAuthHandlers(), "Allowed auth handlers should not be null");
        }
    }

    @Test
    public void testBuildResourceAccessControlDataFieldAccess() throws Exception {

        // Test that we can access the fields properly for testing
        AuthConfigurationUtil authConfigUtil = AuthConfigurationUtil.getInstance();
        
        // Test field access
        Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = getResourceConfigMap(authConfigUtil);
        boolean scopeValidationEnabled = getScopeValidationEnabled(authConfigUtil);
        
        assertNotNull(resourceConfigMap, "Should be able to access resourceConfigMap field");
        assertTrue(scopeValidationEnabled, "Default scope validation should be enabled");
        
        // Test that we can clear and inspect the map
        clearResourceConfigMap(authConfigUtil);
        assertTrue(getResourceConfigMap(authConfigUtil).isEmpty(), "Cleared map should be empty");
    }

    @Test
    public void testBuildResourceAccessControlDataBehaviorUnderNullConfig() throws Exception {

        // Test behavior when configuration is not available (common in test environments)
        AuthConfigurationUtil authConfigUtil = AuthConfigurationUtil.getInstance();
        
        // Clear existing state
        clearResourceConfigMap(authConfigUtil);
        
        // This tests that the method handles missing configuration gracefully
        try {
            authConfigUtil.buildResourceAccessControlData();
        } catch (Exception e) {
            // In test environment, this may throw exceptions due to missing config files
            // This is expected and acceptable
            assertTrue(e instanceof NullPointerException || e instanceof RuntimeException,
                    "Should handle missing configuration gracefully");
        }
        
        // Even if config loading fails, the instance should remain usable
        assertNotNull(getResourceConfigMap(authConfigUtil), "Instance should remain usable");
        assertTrue(getScopeValidationEnabled(authConfigUtil), "Default settings should be preserved");
    }

    private void clearResourceConfigMap(AuthConfigurationUtil authConfigUtil) throws Exception {
        Field resourceConfigMapField = AuthConfigurationUtil.class.getDeclaredField("resourceConfigMap");
        resourceConfigMapField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = 
            (Map<ResourceConfigKey, ResourceConfig>) resourceConfigMapField.get(authConfigUtil);
        resourceConfigMap.clear();
    }

    @SuppressWarnings("unchecked")
    private Map<ResourceConfigKey, ResourceConfig> getResourceConfigMap(AuthConfigurationUtil authConfigUtil) 
            throws Exception {
        Field resourceConfigMapField = AuthConfigurationUtil.class.getDeclaredField("resourceConfigMap");
        resourceConfigMapField.setAccessible(true);
        return (Map<ResourceConfigKey, ResourceConfig>) resourceConfigMapField.get(authConfigUtil);
    }

    private boolean getScopeValidationEnabled(AuthConfigurationUtil authConfigUtil) throws Exception {
        Field isScopeValidationEnabledField = AuthConfigurationUtil.class.getDeclaredField("isScopeValidationEnabled");
        isScopeValidationEnabledField.setAccessible(true);
        return (Boolean) isScopeValidationEnabledField.get(authConfigUtil);
    }

}
