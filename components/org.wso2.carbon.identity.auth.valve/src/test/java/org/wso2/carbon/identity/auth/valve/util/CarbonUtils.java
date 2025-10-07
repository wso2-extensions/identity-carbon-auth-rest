/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.auth.valve.util;

import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.nio.file.Paths;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
/**
 * Utility class for Carbon functions.
 */
public class CarbonUtils {

    public static void setCarbonHome() {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target", "test-classes").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        System.setProperty(CarbonBaseConstants.CARBON_CONFIG_DIR_PATH, Paths.get(carbonHome, "conf").toString());
    }

    public static void mockRealmService(boolean isTenantActive) throws UserStoreException {

        RealmService mockRealmService = mock(RealmService.class);
        AuthenticationValveServiceHolder.getInstance().setRealmService(mockRealmService);

        TenantManager tenantManager = mock(TenantManager.class);
        when(mockRealmService.getTenantManager()).thenReturn(tenantManager);
        when(mockRealmService.getTenantManager().isTenantActive(any(Integer.class))).thenReturn(isTenantActive);
    }
}
