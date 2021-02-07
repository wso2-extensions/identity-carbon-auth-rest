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
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.cors.mgt.core.CORSManagementService;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.service.internal.impl.CORSManagerImpl;

/**
 * Service component class for CORS-Service.
 */
@Component(name = "identity.cors.service.component", immediate = true)
public class CORSServiceComponent {

    private static final Log log = LogFactory.getLog(CORSServiceComponent.class);

    /**
     * Activate the CORSServiceComponent.
     *
     * @param context
     */
    @Activate
    protected void activate(ComponentContext context) {

        try {
            context.getBundleContext().registerService(CORSManager.class, new CORSManagerImpl(), null);
            if (log.isDebugEnabled()) {
                log.debug("CORSServiceComponent is activated.");
            }
        } catch (Throwable e) {
            log.debug("CORSServiceComponent failed to activate.", e);
            // Don't throw the exception.
        }
    }

    /**
     * Deactivate the CORSServiceComponent.
     *
     * @param context
     */
    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("CORSServiceComponent is deactivated.");
        }
    }

    @Reference(
            name = "identity.cors.management.component",
            service = CORSManagementService.class,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCORSManagementService"
    )
    protected void registerCORSManagementService(CORSManagementService corsManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Registering the CORSManagementService in CORSService.");
        }
        CORSServiceHolder.getInstance().setCorsManagementService(corsManagementService);
    }

    protected void unregisterCORSManagementService(CORSManagementService corsManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Unregistering the CORSManagementService in CORSService.");
        }
        CORSServiceHolder.getInstance().setCorsManagementService(null);
    }
}
