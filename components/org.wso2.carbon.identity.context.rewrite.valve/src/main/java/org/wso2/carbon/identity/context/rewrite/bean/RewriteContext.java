/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.context.rewrite.bean;

import java.util.regex.Pattern;

public class RewriteContext {

    private boolean isWebApp;

    private String context;

    private Pattern patternTenant;

    private Pattern patternSuperTenant;

    public RewriteContext(boolean isWebApp, String context) {

        this.isWebApp = isWebApp;
        this.context = context;
        this.patternTenant = Pattern.compile("/t/([^/]+)" + context);
        this.patternSuperTenant = Pattern.compile(context);
    }

    public boolean isWebApp() {

        return isWebApp;
    }

    public void setIsWebApp(boolean isWebApp) {

        this.isWebApp = isWebApp;
    }

    public String getContext() {

        return context;
    }

    public void setContext(String context) {

        this.context = context;
    }

    public Pattern getPatternTenant() {

        return patternTenant;
    }

    public Pattern getPatternSuperTenant() {

        return patternSuperTenant;
    }

    public void setPatternTenant(Pattern patternTenant) {

        this.patternTenant = patternTenant;
    }
}
