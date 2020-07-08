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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.internal.util.CORSConfigurationUtils;
import org.wso2.carbon.identity.cors.mgt.core.model.Origin;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class loads and persists the server level CORS origins.
 */
public class ServerCORSStore {

    private static final Log log = LogFactory.getLog(ServerCORSStore.class);

    private static ValidatedOrigin[] serverCORSOrigins;

    public static ValidatedOrigin[] getServerCORSOrigins() {

        if (serverCORSOrigins == null) {
            List<ValidatedOrigin> validatedOrigins = new ArrayList<>();

            // Get server level allowed CORS origins.
            String allowedOriginsProperty = IdentityUtil.getProperty(IdentityConstants.CORS.ALLOWED_ORIGINS);
            if (StringUtils.isNotBlank(allowedOriginsProperty) && !allowedOriginsProperty.equals("*")) {
                for (Origin origin : CORSConfigurationUtils.parseWords(allowedOriginsProperty).stream().map(Origin::new)
                        .collect(Collectors.toList())) {
                    try {
                        ValidatedOrigin validatedOrigin = new ValidatedOrigin(origin.getValue());
                        validatedOrigins.add(validatedOrigin);
                    } catch (CORSManagementServiceClientException e) {
                        if (log.isDebugEnabled()) {
                            log.debug(e);
                        }
                    }
                }
            }

            serverCORSOrigins = validatedOrigins.toArray(new ValidatedOrigin[0]);
        }

        return serverCORSOrigins;
    }
}
