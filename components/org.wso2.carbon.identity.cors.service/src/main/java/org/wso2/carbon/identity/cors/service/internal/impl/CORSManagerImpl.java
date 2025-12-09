/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.cors.service.internal.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.identity.cors.mgt.core.constant.ErrorMessages;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceServerException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSOrigin;
import org.wso2.carbon.identity.cors.mgt.core.model.Origin;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.service.internal.CORSServiceHolder;
import org.wso2.carbon.identity.cors.service.internal.function.CORSOriginToOrigin;
import org.wso2.carbon.identity.cors.service.internal.store.ServerCORSStore;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * CORSManager implementation.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.cors.service.CORSManager",
                "service.scope=singleton"
        }
)
public class CORSManagerImpl implements CORSManager {

    private static final Log log = LogFactory.getLog(CORSManagerImpl.class);

    @Override
    public Origin[] getCORSOrigins(String tenantDomain) throws CORSManagementServiceServerException {

        List<Origin> originList = new ArrayList<>();
        try {
            // Get CORSOrigins of the server.
            originList.addAll(ServerCORSStore.getServerCORSOrigins());

            // Get CORSOrigins of the tenant.
            List<CORSOrigin> corsOriginList  = CORSServiceHolder.getInstance().getCorsManagementService()
                    .getTenantCORSOrigins(tenantDomain);
            if (!corsOriginList.isEmpty()) {
                originList.addAll(corsOriginList.stream()
                        .map(new CORSOriginToOrigin()).collect(Collectors.toList()));
            }

            return originList.toArray(new Origin[0]);
        } catch (CORSManagementServiceException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_RETRIEVE.getDescription(), tenantDomain), e);
        }
    }

    @Override
    public CORSConfiguration getCORSConfiguration(String tenantDomain) throws CORSManagementServiceException {

        try {
            return CORSServiceHolder.getInstance().getCorsManagementService()
                    .getCORSConfiguration(tenantDomain);
        } catch (CORSManagementServiceException e) {
            throw new CORSManagementServiceServerException(ErrorMessages.ERROR_CODE_CORS_CONFIG_RETRIEVE.getCode(),
                    String.format(ErrorMessages.ERROR_CODE_CORS_CONFIG_RETRIEVE.getDescription(), tenantDomain), e);
        }
    }
}
