using System.Net;
using FluentAssertions;
using Host.TestApps.IntegrationTests.Specs.Glue.OidcProxyNet;
using PuppeteerSharp;
using TechTalk.SpecFlow;

namespace Host.TestApps.IntegrationTests.Specs.Glue;

[Binding]
public class BrowserInteractionSteps(ScenarioContext scenarioContext)
{
    private IBrowser _browser = null!;
    private IPage _page = null!;
    private IResponse _response = null!;

    [Given("the user interacts with the site that implements the OidcProxy with a browser")]
    public async Task StartBrowser()
    {   
        var browserFetcher = new BrowserFetcher(SupportedBrowser.Chrome);
        await browserFetcher.DownloadAsync();

        _browser = await Puppeteer.LaunchAsync(new LaunchOptions
        {
            Headless = true,
            Args = ["--no-sandbox"]
        });
        
        _page = await _browser.NewPageAsync();
        
        await _page.SetUserAgentAsync("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3419.0 Safari/537.36");
    }

    [AfterStep]
    public async Task Authenticate()
    {
        if (scenarioContext.StepContext.StepInfo.Text == "the user's access_token has expired")
        {
            await NavigateToLoginEndpoint();
        }
    }

    [When("the user navigates to (.*)")]
    public async Task NavigateTo(string path)
    {
        var root = scenarioContext["proxyurl"];
        _response = await _page.GoToAsync($"{root}{path}");
    }

    [When(@"the user has authenticated \(navigated to /oauth2/sign_in\)")]
    [Given(@"the user has authenticated \(navigated to /oauth2/sign_in\)")]
    public async Task NavigateToLoginEndpoint()
    {
        var root = scenarioContext["proxyurl"];
        _response = await _page.GoToAsync($"{root}/oauth2/sign_in");
    }
    
    [Given(@"the user has signed out \(navigated to /oauth2/sign_out\)")]
    public async Task NavigateToEndSessionEndpoint()
    {
        var root = scenarioContext["proxyurl"];
        _response = await _page.GoToAsync($"{root}/oauth2/sign_out");
    }

    [When(@"a resource is requested that requires authorization")]
    public async Task NavigateToCustomMeEndpoint()
    {
        var root = scenarioContext["proxyurl"];
        _response = await _page.GoToAsync($"{root}/custom/me");
    }

    [When("the user invokes a downstream API")]
    [When(@"an endpoint is invoked that forwards requests through YARP")]
    public async Task NavigateToEchoEndpoint()
    {
        var root = scenarioContext["proxyurl"];
        _response = await _page.GoToAsync($"{root}/api/echo");
    }

    [Then("the path in the browser equals (.*)")]
    public void AssertUrlEquals(string url)
    {
        var uri = new Uri(_page.Url);
        var root = uri.GetLeftPart(UriPartial.Authority);
        
        _page.Url.Replace(root, string.Empty).Should().Be(url);
    }

    [Then(@"the downstream API receives an AUTHORIZATION header")]
    [Then("access_tokens are forwarded to downstream APIs")]
    public async Task AssertTokensAreForwarded()
    {
        var content = await GetContentFromEchoEndpoint();
        content.Should().Contain("Bearer ey");
    }

    [Then(@"the downstream API does not receive an AUTHORIZATION header")]
    public async Task AssertTokensAreNotForwarded()
    {
        var content = await GetContentFromEchoEndpoint();
        content.Should().NotContain("Bearer ey");
    }

    [Then("the payload of the the ID_TOKEN is visible")]
    public async Task AssertMeEndpointShowsClaims()
    {
        var uri = new Uri(_page.Url);
        var root = uri.GetLeftPart(UriPartial.Authority);
        _response = await _page.GoToAsync($"{root}/oauth2/userinfo");
        
        var content = await _page.GetContentAsync();
        content.Should().Contain("johndoe");
    }
    
    [Then(@"the /me endpoint shows the claims returned by the claims transformation only")]
    public async Task AssertMeEndpointShowsTransformedClaimsOnly()
    {
        var uri = new Uri(_page.Url);
        var root = uri.GetLeftPart(UriPartial.Authority);
        _response = await _page.GoToAsync($"{root}/oauth2/userinfo");
        
        var content = await _page.GetContentAsync();
        content.Should().NotContain("johndoe");
        
        content.Should().Contain("claims");
        content.Should().Contain("Transformed");
    }
    
    [Then(@"the endpoint produces a 200 OK")]
    public void AssertEndpointProducesOK()
    {
        _response.Status.Should().Be(HttpStatusCode.OK);
    }
    
    [Then(@"the response body shows the message ""(.*)""")]
    public async Task AssertResponseBodyContains(string expectedText)
    {
        var text = await _response.TextAsync();
        text.Should().Contain(expectedText);
    }
    
    [Then("the endpoint responds with a 401 unauthorized")]
    public void ThenTheEndpointProducesUnauthenticated()
    {
        _response.Status.Should().Be(HttpStatusCode.Unauthorized);
    }
    
    [Then(@"the user receives a 404 not found")]
    public void ThenTheUserReceivesANotFound()
    {
        _response.Status.Should().Be(HttpStatusCode.NotFound);
    }

    [Then("the ASP.NET Core can use ACCESS_TOKEN claims only")]
    public void AssertAccessTokenClaimsOnly()
    {
        DummyClaimHandler.Claims.Should().NotContain(x => x.Type == "aud");
        DummyClaimHandler.Claims.Should().NotContain(x => x.Type == "azp");
        DummyClaimHandler.Claims.Should().NotContain(x => x.Type == "at_hash");
        
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "scope");
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "jti");
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "name");
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "preferred_username");
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "oi_prst");
        DummyClaimHandler.Claims.Should().Contain(x => x.Type == "client_id");
    }

    [AfterScenario]
    public async Task TearDown()
    {
        await _page!.CloseAsync();
        await _browser!.CloseAsync();
    }
    
    private async Task<string> GetContentFromEchoEndpoint()
    {
        var uri = new Uri(_page.Url);
        var root = uri.GetLeftPart(UriPartial.Authority);
        var pathToEchoEndpoint = $"{root}/api/echo";

        if (_page.Url != pathToEchoEndpoint)
        {
            _response = await _page.GoToAsync(pathToEchoEndpoint);
        }
        
        var content = await _page.GetContentAsync();
        return content;
    }
}