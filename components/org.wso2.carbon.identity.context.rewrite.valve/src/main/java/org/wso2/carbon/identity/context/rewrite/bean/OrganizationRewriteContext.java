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
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ORGANIZATION_PATH_PARAM;

/**
 * Bean for organization qualified context rewrites.
 */
public class OrganizationRewriteContext {

    private boolean isWebApp;
    private String context;
    private Pattern orgContextPattern;
    private List<Pattern> subPaths = new ArrayList<>();

    public OrganizationRewriteContext(boolean isWebApp, String context) {

        this.isWebApp = isWebApp;
        this.context = context;
        this.orgContextPattern = Pattern.compile("^" + ORGANIZATION_PATH_PARAM + "([^/]+)" + context);
    }

    public String getContext() {

        return context;
    }

    public Pattern getOrgContextPattern() {

        return orgContextPattern;
    }

    public List<Pattern> getSubPaths() {

        return subPaths;
    }

    public boolean isWebApp() {

        return isWebApp;
    }

    public void addSubPath(Pattern subPath) {

        this.subPaths.add(subPath);
    }
}
