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
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
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

}
