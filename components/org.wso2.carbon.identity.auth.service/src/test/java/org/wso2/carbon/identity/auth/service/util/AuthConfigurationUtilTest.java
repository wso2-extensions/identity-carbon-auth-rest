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

public class AuthConfigurationUtilTest {

    @Mock
    private OrganizationManager mockedOrganizationManager;

    @BeforeClass
    public void setUpClass() {

        MockitoAnnotations.initMocks(this);
        AuthenticationServiceHolder.getInstance().setOrganizationManager(mockedOrganizationManager);
    }

    @DataProvider(name = "requestURIProvider")
    public Object[][] requestURIProvider() {

        return new Object[][]{
                {"/t/tenant1/o/b0d4d224-6276-4b97-8553-686af86d2ef2/oauth2/token", "tenant-domain"},
                {"https://localhost:9443/t/tenant1/o/b0d4d224-6276-4b97-8553-686af86d2ef2/oauth2/token", null}
        };
    }

    @Test(dataProvider = "requestURIProvider")
    public void testGetResourceResidentTenantForTenantPerspective(String requestURI, String expectedValue) throws Exception {

        when(mockedOrganizationManager.resolveTenantDomain("b0d4d224-6276-4b97-8553-686af86d2ef2")).thenReturn(
                expectedValue);
        String tenantDomain = AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective(requestURI);
        assertEquals(tenantDomain, expectedValue);
    }

    @Test
    public void testGetResourceResidentTenantForTenantPerspectiveWithException() throws Exception {

        when(mockedOrganizationManager.resolveTenantDomain("b0d4d224-6276-4b97-8553-686af86d2ef2")).
                thenThrow(OrganizationManagementException.class);
        String tenantDomain = AuthConfigurationUtil.getResourceResidentTenantForTenantPerspective(
                "/t/tenant1/o/b0d4d224-6276-4b97-8553-686af86d2ef2/oauth2/token");
        assertNull(tenantDomain);
    }
}
