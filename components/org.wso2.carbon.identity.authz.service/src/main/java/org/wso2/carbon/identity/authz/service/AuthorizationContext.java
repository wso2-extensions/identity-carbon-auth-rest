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
package org.wso2.carbon.identity.authz.service;


import org.wso2.carbon.identity.core.bean.context.MessageContext;

import java.util.ArrayList;
import java.util.List;

public class AuthorizationContext extends MessageContext{


    private String context ;
    private String httpMethods;

    private String userName ;
    private String permissionString ;


    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPermissionString() {
        return permissionString;
    }

    public void setPermissionString(String permissionString) {
        this.permissionString = permissionString;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getHttpMethods() {
        return httpMethods;
    }

    public void setHttpMethods(String httpMethods) {
        this.httpMethods = httpMethods;
    }
}
