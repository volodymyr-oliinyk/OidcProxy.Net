# OidcProxy.Net.EntraId

This package contains the software you need to implement the BFF Security Pattern. This software does three things:

1. It manages the user session
2. It allows the user to log into the site
3. It forwards request to downstream services and adds the Authorization header with the user's access token to the requests

OidcProxy.Net is a stateful reverse proxy. To forward requests to downstream services OidcProxy.Net uses YARP.

Currently, OidcProxy.Net supports logging in with Azure, Auth0, IdentityServer4, and any other OpenID Connect compliant authorization server. Currently, only the Authorization Code flow with Proof-Key Client Exchange is supported.

## Quickstart: Implementing the BFF Security Pattern

To build it, execute the following commands:

```bash
dotnet new web
dotnet add package OidcProxy.Net.EntraId
```

Create the following `Program.cs` file:

```csharp
using OidcProxy.Net.EntraId;
using OidcProxy.Net.ModuleInitializers;

var builder = WebApplication.CreateBuilder(args);

var entraIdConfig = builder.Configuration
    .GetSection("OidcProxy")
    .Get<EntraIdProxyConfig>();

builder.Services.AddEntraIdProxy(entraIdConfig);

var app = builder.Build();

app.UseEntraIdProxy();

app.Run();

```

Create the following `appsettings.json` file:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "EntraId": {
    "ClientId": "{yourClientId}",
    "ClientSecret": "{yourClientSecret}",
    "TenantId": "{yourTenantId}",
    "DiscoveryEndpoint": "{https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration}",
    "Scopes": [
      "openid", "profile", "offline_access", "https://yourDomain.onmicrosoft.com/test/api1"
    ]
  },
  "AllowedHosts": "*",
  "OidcProxy": {
    "LandingPage": "/hello",
    "EntraId": {
      "ClientId": "{yourClientId}",
      "ClientSecret": "{yourClientSecret}",
      "Scopes": [
        "openid",
        "profile",
        "offline_access",
        "https://foo.onmicrosoft.com/api/test/weatherforecast.read"
      ]
    },
    "ReverseProxy": {
      "Routes": {
        "api": {
          "ClusterId": "api",
          "Match": {
            "Path": "/api/{*any}"
          }
        }
      },
      "Clusters": {
        "api": {
          "Destinations": {
            "api/node1": {
              "Address": "https://{your_api}/"
            }
          }
        }
      }
    }
  }
}
```

In this example we assume you are running a Single Page Application on localhost on port `4200` and you have an API running at localhost on port `8080`. If that is not the case, then update the `appsettings.json` accordingly.

To run it, type `dotnet run` or just hit the 'play'-button in Visual Studio.

## Endpoints

The proxy relays all requests as configured in the `ReverseProxy` section in the `appsettings.json` file, except for four endpoints:

### [GET] /oauth2/sign_in
To log a user in and to start a http session, navigate to `/oauth2/sign_in`. The software will redirect to the login page of the Identity Provider to log the user in. The resulting tokens will be stored in the user session and are not available in the browser.

### [GET] /oauth2/callback
This endpoint is used by the IdentityProvider.

### [GET] /oauth2/userinfo
To see the logged in user, navigate to the `/oauth2/userinfo` endpoint. This endpoint shows the claims that are in the `id_token`.

### [GET] /oauth2/sign_out
To revoke the tokens that have been obtained when the user logged in, execute a get request on the `/oauth2/sign_out` endpoint. This will revoke the tokens that have been stored in the user session and will not log the user out from the Identity Provider session. This must be implemented at client side.

## Issues

Are you encountering issues? Please let us know at: https://github.com/thecloudnativewebapp/OidcProxy.Net/issues