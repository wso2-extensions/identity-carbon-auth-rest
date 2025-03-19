package org.wso2.carbon.identity.auth.service.util;

import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.nio.file.Paths;

/**
 * Common test utilities.
 */
public class CommonTestUtils {

    private CommonTestUtils() {
    }

    /**
     * Initialize privileged carbon context for tests.
     *
     * @param tenantDomain Tenant domain.
     * @param tenantID     Tenant ID.
     */
    public static void initPrivilegedCarbonContext(String tenantDomain, int tenantID) {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("testUser");
    }

    /**
     * Initialize privileged carbon context for tests.
     */
    public static void initPrivilegedCarbonContext() {

        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        int tenantID = MultitenantConstants.SUPER_TENANT_ID;
        initPrivilegedCarbonContext(tenantDomain, tenantID);
    }
}