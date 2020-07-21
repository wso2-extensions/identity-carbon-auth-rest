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

package org.wso2.carbon.identity.cors.service.internal.store;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.internal.util.CORSConfigurationUtils;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;

import java.util.List;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.cors.service.constant.ErrorMessages.ERROR_CODE_INVALID_ORIGIN;

/**
 * This class loads and persists the server level CORS origins.
 */
public class ServerCORSStore {

    private static final Log log = LogFactory.getLog(ServerCORSStore.class);

    private static List<ValidatedOrigin> serverCORSOrigins;

    public static List<ValidatedOrigin> getServerCORSOrigins() {

        if (serverCORSOrigins == null) {
            // Get server level allowed CORS origins.

            serverCORSOrigins = CORSConfigurationUtils.readPropertyArray(IdentityConstants.CORS.ALLOWED_ORIGINS)
                    .stream().map(origin -> {
                        try {
                            return new ValidatedOrigin(origin);
                        } catch (CORSManagementServiceClientException e) {
                            log.error(String.format(ERROR_CODE_INVALID_ORIGIN.getDescription(), origin), e);
                        }
                        return null;
                    }).collect(Collectors.toList());
        }

        return serverCORSOrigins;
    }
}
