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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cors.service.internal.function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceClientException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSOrigin;
import org.wso2.carbon.identity.cors.mgt.core.model.ValidatedOrigin;
import org.wso2.carbon.identity.cors.service.internal.impl.CORSManagerImpl;

import java.util.function.Function;

import static org.wso2.carbon.identity.cors.service.constant.ErrorMessages.ERROR_CODE_INVALID_STORED_ORIGIN;


/**
 * Converts a CORSOrigin object to a ValidatedOrigin object.
 */
public class CORSOriginToValidatedOrigin implements Function<CORSOrigin, ValidatedOrigin> {

    private static final Log log = LogFactory.getLog(CORSManagerImpl.class);

    @Override
    public ValidatedOrigin apply(CORSOrigin corsOrigin) {

        ValidatedOrigin validatedOrigin = null;
        try {
            validatedOrigin = new ValidatedOrigin(corsOrigin.getOrigin());
        } catch (CORSManagementServiceClientException e) {
            // The program should never reach here as all the CORS origins in the database are already validated.
            log.error(String.format(ERROR_CODE_INVALID_STORED_ORIGIN.getDescription(), corsOrigin.getOrigin()), e);
        }
        return validatedOrigin;
    }
}
