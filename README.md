# REST Authentication and Authorization extension on Identity Server

This contains
* Generic Authentication and Authorization Framework
* MSF4J Interceptors used in Authentication and Authorization

## Architecture

The framework is based on Authentication Handlers and Resource Handlers

* Authentication handler: Provides protocol level handling of authentication
e.g. Basic Authentication
* Resource Handler evaluates each request and decides which permission to be applied to each request.


##Supported Authentication Handler
* Basic Authentication


##Supported Resurce handler
A Default Authentication handler having the following hardcoded resources are provided by default.
Note that this is same as one provided in Identity.xml in Identity Server v5.3.0

```xml
<ResourceAccessControl>
     <Resource context="(.*)/api/identity/user/(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/api/identity/recovery/(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/.well-known(.*)" secured="true" http-method="all"/>
     <Resource context="(.*)/identity/register(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/delete</Permissions>
     </Resource>
     <Resource context="(.*)/identity/connect/register(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/create</Permissions>
     </Resource>
     <Resource context="(.*)/oauth2/introspect(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/applicationmgt/view</Permissions>
     </Resource>
     <Resource context="(.*)/api/identity/entitlement/(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage/identity/pep</Permissions>
     </Resource>

     <!-- SCIM Defaults -->
     <Resource context="(.*)/scim/v2/Me" secured="true" http-method="all" />
     <Resource context="(.*)/scim/v2/ServiceProviderConfig" secured="true" http-method="all" />
     <Resource context="(.*)/scim/v2/ResourceType" secured="true" http-method="all" />
     <Resource context="(.*)/scim/v2/(.*)" secured="true" http-method="all">
     <Permissions>/permission/admin/manage</Permissions>
     </Resource>
</ResourceAccessControl>
```


## Adding a Resource Handler
A resource handler can be added wit OSGI service registration

e.g,
```java
getBundleContext().registerService(ResourceHandler.class, myResourceHandlerImpl, null);
```



## Adding a Authentication Handler
An Authentication  handler can be added wit OSGI service registration

e.g,
```java
getBundleContext().registerService(AuthenticationHandler.class, myAuthHandlerImpl, null);
```


### Complete Feature List (Yet to be done)
* Client Authentication
* OAuth Authorization
* Client Certificate Authentication
* Configurable Resource mapping similar to Identity.xml in IS 5.3.0

