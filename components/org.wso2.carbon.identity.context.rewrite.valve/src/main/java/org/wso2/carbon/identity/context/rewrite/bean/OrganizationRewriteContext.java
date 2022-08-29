/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.context.rewrite.bean;

import java.util.ArrayList;
import java.util.List;

/**
 * Bean for organization qualified context rewrites.
 */
public class OrganizationRewriteContext {

    private boolean isWebApp;
    private String context;
    private List<String> subContexts = new ArrayList<>();

    public OrganizationRewriteContext(boolean isWebApp, String context) {

        this.isWebApp = isWebApp;
        this.context = context;
    }

    public String getContext() {

        return context;
    }

    public List<String> getSubContexts() {

        return subContexts;
    }

    public boolean isWebApp() {

        return isWebApp;
    }

    public void addSubContext(String subContext) {

        this.subContexts.add(subContext);
    }
}
