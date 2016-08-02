package org.wso2.carbon.identity.auth.valve.util;

import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;
import org.wso2.carbon.identity.core.handler.HandlerManager;

import java.util.List;

public class AuthHandlerManager {
    private static AuthHandlerManager authHandlerManager = new AuthHandlerManager();

    private AuthHandlerManager() {

    }

    public static AuthHandlerManager getInstance() {
        return AuthHandlerManager.authHandlerManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        List<AuthenticationManager> authenticationManagers =
                AuthenticationValveServiceHolder.getInstance().getAuthenticationManagers();
        AuthenticationManager authenticationManager = HandlerManager.getInstance().
                                                                getFirstPriorityHandler(authenticationManagers, true);
        return authenticationManager;
    }
}
