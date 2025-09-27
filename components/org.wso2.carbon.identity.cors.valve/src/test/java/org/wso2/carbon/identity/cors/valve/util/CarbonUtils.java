/*
 * Copyright (c) 2020-2025, WSO2 LLC. (https://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cors.valve.util;

import org.mockito.MockedStatic;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

/**
 * Utility class for Carbon functions.
 */
public class CarbonUtils {

    public static void setCarbonHome() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());
    }

    public static void mockCarbonContextForTenant(int tenantId, String tenantDomain) {

        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        try (MockedStatic<PrivilegedCarbonContext> mockedStatic = mockStatic(PrivilegedCarbonContext.class)) {
            mockedStatic.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getTenantDomain()).thenReturn(tenantDomain);
            when(privilegedCarbonContext.getTenantId()).thenReturn(tenantId);
            when(privilegedCarbonContext.getUsername()).thenReturn("admin");
        }
    }

    public static void mockIdentityTenantUtility() {

        IdentityTenantUtil identityTenantUtil = mock(IdentityTenantUtil.class);
        try (MockedStatic<IdentityTenantUtil> mockedStatic = mockStatic(IdentityTenantUtil.class)) {
            mockedStatic.when(() -> IdentityTenantUtil.getTenantDomain(any(Integer.class)))
                    .thenReturn(SUPER_TENANT_DOMAIN_NAME);
        }
    }

    public static void mockRealmService() {

        RealmService mockRealmService = mock(RealmService.class);
        TenantManager tenantManager = mock(TenantManager.class);
        when(mockRealmService.getTenantManager()).thenReturn(tenantManager);
        FrameworkServiceDataHolder.getInstance().setRealmService(mockRealmService);
    }
}
