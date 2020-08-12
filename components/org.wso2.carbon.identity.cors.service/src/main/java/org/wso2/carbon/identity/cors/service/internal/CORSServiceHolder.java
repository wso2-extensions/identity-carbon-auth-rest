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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSConfigurationDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.CORSOriginDAO;
import org.wso2.carbon.identity.cors.mgt.core.dao.impl.CORSConfigurationDAOImpl;
import org.wso2.carbon.identity.cors.mgt.core.dao.impl.CORSOriginDAOImpl;

/**
 * Service holder class for CORS-Service.
 */
public class CORSServiceHolder {

    private static final Log log = LogFactory.getLog(CORSServiceHolder.class);

    private CORSOriginDAO corsOriginDAO = new CORSOriginDAOImpl();
    private CORSConfigurationDAO corsConfigurationDAO = new CORSConfigurationDAOImpl();

    private CORSServiceHolder() {

    }

    public static CORSServiceHolder getInstance() {

        return CORSServiceHolder.SingletonHelper.INSTANCE;
    }

    public CORSOriginDAO getCorsOriginDAO() {

        return corsOriginDAO;
    }

    public void setCorsOriginDAO(CORSOriginDAO corsOriginDAO) {

        if (corsOriginDAO == null) {
            this.corsOriginDAO = null;
        } else if (corsOriginDAO.getPriority() > this.corsOriginDAO.getPriority()) {
            log.info(String.format("Replacing the CORSOriginDAO of priority %s " +
                            "with a CORSOriginDAO of priority %s.",
                    this.corsOriginDAO.getPriority(), corsOriginDAO.getPriority()));
            this.corsOriginDAO = corsOriginDAO;
        }
    }

    public CORSConfigurationDAO getCorsConfigurationDAO() {

        return corsConfigurationDAO;
    }

    public void setCorsConfigurationDAO(CORSConfigurationDAO corsConfigurationDAO) {

        if (corsConfigurationDAO == null) {
            this.corsConfigurationDAO = null;
        } else if (corsConfigurationDAO.getPriority() > this.corsConfigurationDAO.getPriority()) {
            log.info(String.format("Replacing the CORSConfigurationDAO of priority %s " +
                            "with a CORSConfigurationDAO of priority %s.",
                    this.corsOriginDAO.getPriority(), corsOriginDAO.getPriority()));
            this.corsConfigurationDAO = corsConfigurationDAO;
        }
    }

    /**
     * SingletonHelper for the singleton instance of CORSServiceHolder.
     */
    private static class SingletonHelper {

        private static final CORSServiceHolder INSTANCE = new CORSServiceHolder();
    }
}
