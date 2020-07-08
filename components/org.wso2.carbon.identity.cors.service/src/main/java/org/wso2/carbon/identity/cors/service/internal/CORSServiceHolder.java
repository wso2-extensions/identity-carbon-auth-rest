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

package org.wso2.carbon.identity.cors.service.internal;

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.cors.service.CORSManager;

/**
 * Service holder class for CORS-Service.
 */
public class CORSServiceHolder {

    private ConfigurationManager configurationManager;

    private CORSManager corsManager;

    private CORSServiceHolder() {

    }

    public static CORSServiceHolder getInstance() {

        return CORSServiceHolder.SingletonHelper.INSTANCE;
    }

    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    public CORSManager getCorsManager() {

        return corsManager;
    }

    public void setCorsManager(CORSManager corsManager) {

        this.corsManager = corsManager;
    }

    /**
     * SingletonHelper for the singleton instance of CORSServiceHolder.
     */
    private static class SingletonHelper {

        private static final CORSServiceHolder INSTANCE = new CORSServiceHolder();
    }
}
