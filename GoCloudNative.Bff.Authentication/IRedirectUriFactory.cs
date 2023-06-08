using Microsoft.AspNetCore.Http;

namespace GoCloudNative.Bff.Authentication;

internal interface IRedirectUriFactory
{
    string DetermineHostName(HttpContext context);
    string DetermineRedirectUri(HttpContext context, string endpointName);
}