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

    private Pattern tenantContextPattern;

    private Pattern baseContextPattern;

    private static final String CONSOLE_CONTEXT = "/console/";

    public RewriteContext(boolean isWebApp, String context) {

        this.isWebApp = isWebApp;
        this.context = context;
        this.tenantContextPattern = this.isWebApp ? CONSOLE_CONTEXT.equals(context)
                ? Pattern.compile("^/t/([^/]+)(/o|/o/([^/]+))?" + context)
                : Pattern.compile("^/t/([^/]+)(/o)?" + context)
                : Pattern.compile("^/t/([^/]+)" + context);
        this.baseContextPattern = Pattern.compile("^" + context);
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

    public Pattern getTenantContextPattern() {

        return tenantContextPattern;
    }

    public Pattern getBaseContextPattern() {

        return baseContextPattern;
    }

    public void setTenantContextPattern(Pattern tenantContextPattern) {

        this.tenantContextPattern = tenantContextPattern;
    }

    /**
     * @deprecated as of release 1.4.1
     * Replaced by getTenantContextPattern()
     */
    @Deprecated
    public Pattern getPattern() {

        return tenantContextPattern;
    }

    /**
     * @deprecated as of release 1.4.1
     * Replaced by setTenantContextPattern(Pattern tenantContextPattern)
     */
    @Deprecated
    public void setPattern(Pattern pattern) {

        this.tenantContextPattern = pattern;
    }
}
