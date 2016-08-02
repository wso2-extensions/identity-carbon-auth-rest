package org.wso2.carbon.identity.auth.service.util;


import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.model.ResourceAccessControlConfig;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;

import javax.xml.namespace.QName;
import java.util.Iterator;

public class AuthConfigurationUtil {

    private static AuthConfigurationUtil authConfigurationUtil = new AuthConfigurationUtil();

    private AuthConfigurationUtil(){
    }

    public static AuthConfigurationUtil getInstance(){
        return AuthConfigurationUtil.authConfigurationUtil;
    }

    /**
     * Build rest api resource control config.
     */
    public void buildResourceAccessControlData() {

        OMElement resourceAccessControl = IdentityConfigParser.getInstance().getConfigElement(IdentityConstants.RESOURCE_ACCESS_CONTROL_ELE);
        if (resourceAccessControl != null) {

            Iterator<OMElement> resources = resourceAccessControl.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, IdentityConstants.RESOURCE_ELE));
            if (resources != null) {

                while (resources.hasNext()) {
                    OMElement resource = resources.next();
                    ResourceAccessControlConfig resourceAccessControlConfig = new ResourceAccessControlConfig();

                    String context = resource.getAttributeValue(new QName(IdentityConstants.RESOURCE_CONTEXT_ATTR));
                    String httpMethod = resource.getAttributeValue(
                            new QName(IdentityConstants.RESOURCE_HTTP_METHOD_ATTR));
                    String isSecured = resource.getAttributeValue(new QName(IdentityConstants.RESOURCE_SECURED_ATTR));

                    StringBuilder permissionBuilder = new StringBuilder();
                    Iterator<OMElement> permissionsIterator = resource.getChildrenWithName(
                            new QName(IdentityConstants.RESOURCE_PERMISSION_ELE));
                    if (permissionsIterator != null) {
                        while (permissionsIterator.hasNext()) {
                            OMElement permissionElement = permissionsIterator.next();
                            String permission = permissionElement.getText();
                            if (StringUtils.isNotEmpty(permissionBuilder.toString()) &&
                                    StringUtils.isNotEmpty(permission)) {
                                permissionBuilder.append(",");
                            }
                            if (StringUtils.isNotEmpty(permission)) {
                                permissionBuilder.append(permission);
                            }
                        }
                    }

                    resourceAccessControlConfig.setContext(context);
                    resourceAccessControlConfig.setHttpMethod(httpMethod);
                    if (StringUtils.isNotEmpty(isSecured) && (Boolean.TRUE.toString().equals(isSecured) ||
                            Boolean.FALSE.toString().equals(isSecured))) {
                        resourceAccessControlConfig.setIsSecured(Boolean.parseBoolean(isSecured));
                    }
                    resourceAccessControlConfig.setPermissions(permissionBuilder.toString());

                    ResourceAccessControlConfig.ResourceKey resourceKey = new ResourceAccessControlConfig.ResourceKey();
                    resourceKey.setContext(context);
                    resourceKey.setHttpMethod(httpMethod);

                    //resourceAccessControlConfigHolder.put(resourceKey, resourceAccessControlConfig);
                }
            }
        }
    }
}
