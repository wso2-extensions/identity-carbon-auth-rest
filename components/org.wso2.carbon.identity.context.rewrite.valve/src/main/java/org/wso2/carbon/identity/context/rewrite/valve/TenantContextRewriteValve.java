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

package org.wso2.carbon.identity.context.rewrite.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.wso2.carbon.identity.context.rewrite.util.Utils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class TenantContextRewriteValve extends ValveBase {

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String requestURI = request.getRequestURI();

        List<String> restrictedContexts = getRestrictedContexts();
        String contextToForward = null;

        boolean isContextRewrite = false;

        //Get the rewrite contexts and check whether request URI contains any of rewrite contains.
        for (String context : restrictedContexts) {
            if (requestURI.contains(context)) {
                isContextRewrite = true;
                contextToForward = context;
                break;
            }
        }

        //request URI is not a rewrite one
        if (!isContextRewrite) {
            getNext().invoke(request, response);
            return;
        }

        String tenantDomain = Utils.getTenantDomainFromURLMapping(request);

        String dispatchLocation;
        if (requestURI.contains("/t/")) {
            dispatchLocation = requestURI.replace("/t/" + tenantDomain + contextToForward, "");
        } else {
            dispatchLocation = requestURI.replace(contextToForward, "");
        }

        //Dispatch request to new endpoint
        request.getServletContext().getContext(contextToForward).getRequestDispatcher("/" + dispatchLocation).forward
                (request, response);
    }


    private List<String> getRestrictedContexts() {
        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object value = configuration.get("TenantContextsToRewrite.context");
        if (value == null) {
            return new ArrayList<>();
        }
        if (value instanceof ArrayList) {
            return (ArrayList<String>) value;
        } else {
            List<String> list = new ArrayList<>();
            list.add(value.toString());
            return list;
        }
    }
}
