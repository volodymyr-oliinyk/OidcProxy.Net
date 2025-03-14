Feature: Token forwarding

Scenario: Unauthenticated users
Given the user interacts with the site that implements the OidcProxy with a browser
 When the user invokes a downstream API
 Then the downstream API does not receive an AUTHORIZATION header

Scenario: Authenticated users
Given the user interacts with the site that implements the OidcProxy with a browser
  And the user has authenticated (navigated to /oauth2/sign_in)
 When the user invokes a downstream API
 Then the downstream API receives an AUTHORIZATION header
 
 Scenario: Token expired - refresh-tokens
 Given the user interacts with the site that implements the OidcProxy with a browser
   And the user has authenticated (navigated to /oauth2/sign_in)
   And the user's access_token has expired
  When the user invokes a downstream API
  Then the OidcProxy obtains a new token
   And the downstream API receives an AUTHORIZATION header
  
 Scenario: Authenticated users in AuthenticateOnly-Mode
 Given the user interacts with the site that implements the OidcProxy with a browser
   And the proxy runs in AuthenticateOnly-Mode
   And the user has authenticated (navigated to /oauth2/sign_in)
  When the user invokes a downstream API
  Then the user receives a 404 not found
 
Scenario: Signing out
Given the user interacts with the site that implements the OidcProxy with a browser
  And the user has authenticated (navigated to /oauth2/sign_in)
  And the user has signed out (navigated to /oauth2/sign_out)
 When the user invokes a downstream API
 Then the downstream API does not receive an AUTHORIZATION header
 
 


