using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Azure.Core;
using System.Threading;
using System.Net.Http;
using System.IO;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Net;
using Azure.Identity;

namespace ASPCoreWithKV
{
    public class HybridManagedIdentityCredential : TokenCredential
    {
        private readonly HttpClient _client;
        private readonly Dictionary<string, AccessToken> _tokens;
        public HybridManagedIdentityCredential() : this(new HttpClient()) { }
        public HybridManagedIdentityCredential(IHttpClientFactory clientFactory) : this(clientFactory.CreateClient()) { }
        public HybridManagedIdentityCredential(HttpClient client)
        {
            _client = client;
            _client.DefaultRequestHeaders.TryAddWithoutValidation("Metadata", "true");
            _tokens = new Dictionary<string, AccessToken>();
        }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return GetAccessTokenAsync(requestContext.Scopes).Result;
        }

        public async override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return await GetAccessTokenAsync(requestContext.Scopes);
        }

        private async Task<AccessToken> GetAccessTokenAsync(string[] scopes)
        {
            var resource = ScopeUtils.ScopesToResource(scopes);
            if (_tokens.ContainsKey(resource) && _tokens.TryGetValue(resource, out var token))
            {
                if (token.ExpiresOn > DateTime.UtcNow)
                {
                    return token;
                }
                _tokens.Remove(resource);
            }

            _tokens.TryAdd(resource, await GetAccessTokenFromEndpoint(resource));
            return await GetAccessTokenAsync(scopes);
        }

        // sample implementation, not production ready; 
        // when using MSI with Azure Arc, the process is different from regular MSIs in Azure
        // the endpoint is available in the IDENITY_ENDPOINT variable after Arc onboarding
        // the call is made twice - the first time, to generate and authentication header
        // the authentication header value is stored in a file, the path to which is returned
        // in the WWW-Authenticate header
        // Note that the OS account running the app (your account, a service account, whatever)
        // will need permission to read that file in order to get the header
        // Once the file is open, read the data and use that in the second call to actually receive an access_token
        
        private async Task<AccessToken> GetAccessTokenFromEndpoint(string resource)
        {
            var localIdentityEndpoint = Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT");
            if (string.IsNullOrWhiteSpace(localIdentityEndpoint)) throw new CredentialUnavailableException("No hybrid IMDS endpoint found");

            var url = new Uri($"{localIdentityEndpoint}?api-version=2020-06-01&resource={resource}");
            Console.WriteLine($"Getting token from: {url} for resource: {resource}");

            var response = await _client.GetAsync(url);
            if (!response.IsSuccessStatusCode && response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var wwwAuthHeader = response.Headers.WwwAuthenticate.ToString();
                var filePath = wwwAuthHeader.Split(' ')[1].Split('=')[1];
                Console.WriteLine($"Getting token data from path: {filePath}");

                if (string.IsNullOrWhiteSpace(filePath)) { throw new Exception("no file"); }
                var tokenFileData = await File.ReadAllTextAsync(filePath);
                _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", tokenFileData);

                var authResponse = await _client.GetAsync(url);
                var receivedToken = JsonSerializer.Deserialize<MsiTokenResponse>(await authResponse.Content.ReadAsStringAsync()); // stream?
                var tokenExpiresOn = DateTimeOffset.FromUnixTimeSeconds(long.Parse(receivedToken.ExpiresOn));
                return new AccessToken(receivedToken.AccessToken, tokenExpiresOn);
            }
            throw new CredentialUnavailableException($"Hybrid IMDS not available; {await response.Content.ReadAsStringAsync()}");
        }
    }

    // see: https://github.com/azure-sdk/azure-sdk-for-net/blob/master/sdk/identity/Azure.Identity/src/ScopeUtilities.cs
    public class ScopeUtils
    {
        private const string DefaultSuffix = "/.default";
        public static string ScopesToResource(string[] scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            if (scopes.Length != 1)
            {
                throw new ArgumentException("To convert to a resource string the specified array must be exactly length 1", nameof(scopes));
            }

            if (!scopes[0].EndsWith(DefaultSuffix, StringComparison.Ordinal))
            {
                return scopes[0];
            }

            return scopes[0].Remove(scopes[0].LastIndexOf(DefaultSuffix, StringComparison.Ordinal));
        }
    }
    public class MsiTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }

        [JsonPropertyName("expires_in")]
        public string ExpiresIn { get; set; }

        [JsonPropertyName("expires_on")]
        public string ExpiresOn { get; set; }

        [JsonPropertyName("not_before")]
        public string NotBefore { get; set; }

        [JsonPropertyName("resource")]
        public string Resource { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }
    }
}
