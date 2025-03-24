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

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;

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

        MockitoAnnotations.initMocks(this);
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
}
