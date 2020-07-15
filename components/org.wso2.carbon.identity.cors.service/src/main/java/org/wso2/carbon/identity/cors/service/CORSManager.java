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

package org.wso2.carbon.identity.cors.service;

import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceServerException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;

/**
 * CORSManager interface.
 */
public interface CORSManager {

    /**
     * Get all the CORS Origins belonging to a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return ValidatedOrigin[] Returns an array of validated CORS origins configured by the tenant.
     * @throws CORSManagementServiceClientException
     * @throws CORSManagementServiceServerException
     */
    ValidatedOrigin[] getCORSOrigins(String tenantDomain) throws CORSManagementServiceClientException,
            CORSManagementServiceServerException;

    /**
     * Get the CORS configurations of a tenant.
     *
     * @param tenantDomain The tenant domain.
     * @return CORSConfiguration Returns an instance of {@code CORSConfiguration} belonging to the tenant.
     * @throws CORSManagementServiceException
     */
    CORSConfiguration getCORSConfiguration(String tenantDomain) throws CORSManagementServiceException;
}
