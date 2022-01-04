/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.ServerConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.Cookie;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.auth.service.util.Constants.COOKIE_AUTH_HEADER;
import static org.wso2.carbon.identity.auth.service.util.Constants.JSESSIONID;

/**
 * This handler is used to authenticate the rest APIs based on the set-cookie obtained from the AuthenticationAdmin
 * Service.
 */
public class TomcatCookieAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(TomcatCookieAuthenticationHandler.class);

    @Override
    public String getName() {

        return "TomcatCookieAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 500);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                Cookie[] cookies = authenticationContext.getAuthenticationRequest().getCookies();
                for (Cookie cookie : cookies) {
                    if (cookie.getName().equals(JSESSIONID)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;

        if (servletRequestExists(authenticationContext)) {
            Request request = (Request) authenticationContext.getAuthenticationRequest().getAttribute(HTTPConstants
                    .MC_HTTP_SERVLETREQUEST);
            if (isLoggedInUserExists(request)) {
                String userName = (String) request.getSession().getAttribute(ServerConstants.USER_LOGGED_IN);
                if (isNotBlank(userName)) {
                    String tenantDomain = (String) request.getSession().getAttribute(MultitenantConstants.TENANT_DOMAIN);
                    User user = buildUser(userName, tenantDomain);
                    authenticationContext.setUser(user);
                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                    if (log.isDebugEnabled()) {
                        log.debug("Tomcat Cookie Authentication success.");
                    }
                }
            }
        }

        if (AuthenticationStatus.FAILED.equals(authenticationResult.getAuthenticationStatus())) {
            if (log.isDebugEnabled()) {
                log.debug("Tomcat Cookie Authentication Failed.");
            }
        }
        return authenticationResult;
    }

    private boolean isLoggedInUserExists(Request request) {

        return request != null && request.getSession() != null && request.getSession().getAttribute(ServerConstants
                .USER_LOGGED_IN) != null;
    }

    private User buildUser(String userName, String tenantDomain) {

        String userStoreDomain = UserCoreUtil.extractDomainFromName(userName);
        userName = UserCoreUtil.removeDomainFromName(userName);

        User user = new User();
        user.setUserName(MultitenantUtils.getTenantAwareUsername(userName));
        user.setTenantDomain(tenantDomain);
        user.setUserStoreDomain(userStoreDomain);
        return user;
    }

    private boolean servletRequestExists(AuthenticationContext authenticationContext) {

        Object request = authenticationContext.getAuthenticationRequest().getAttribute(HTTPConstants
                .MC_HTTP_SERVLETREQUEST);
        return request != null && request instanceof Request;
    }
}
