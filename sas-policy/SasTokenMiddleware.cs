using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace N2.Security.Sas;

public class SasTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ISasTokenValidator _sasTokenValidator;
    private readonly ISasPolicyRepository _claimsRepository;
    private readonly ILogger<SasTokenMiddleware> _logger;

    public SasTokenMiddleware(
        RequestDelegate next,
        ISasTokenValidator sasTokenValidator,
        ISasPolicyRepository claimsRepository,
        ILogger<SasTokenMiddleware> logger
        )
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _sasTokenValidator = sasTokenValidator ?? throw new ArgumentNullException(nameof(sasTokenValidator));
        _claimsRepository = claimsRepository ?? throw new ArgumentNullException(nameof(claimsRepository));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Extract the token from the Authorization header
        var requestPath = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}";
        var requestUri = new Uri(requestPath, UriKind.Absolute);

        // Get the properties from the request headers
        var token = SasTokenFactory.FromHeaders(context.Request.Headers);

        // Validate the token
        var validationResult = await _sasTokenValidator.Validate(requestUri, token);

        if (!validationResult.Success)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            _logger.LogWarning($"{validationResult.TokenResponseCode} : {validationResult.TokenResponseCode.Description()}");
            await context.Response.WriteAsync($"Unauthorized: {validationResult.TokenResponseCode}");
            return;
        }

        // Check if the signing key is valid, returns null if not found
        var signingKeyClaims = await _claimsRepository.GetPolicy(token.SigningKeyName);
        if (signingKeyClaims == null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            _logger.LogWarning($"Invalid signing key: {token.SigningKeyName} not found.");
            await context.Response.WriteAsync($"Unauthorized: {TokenResponseCode.PolicyNotFound}");
            return;
        }

        // Create claims based on the token
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, token.SigningKeyName),
            new(ClaimTypes.Expiration, token.Expiry.ToString())
        };

        foreach (var resource in token.SharedResource)
        {
            claims.Add(new Claim(ClaimTypes.Role, resource));
        }

        // Add additional claims based on the `skn` parameter
        if (signingKeyClaims.HasClaims)
        {
            var additionalClaims = await _claimsRepository.GetPolicyClaims(token.SigningKeyName);
            foreach (var claim in additionalClaims)
            {
                claims.Add(new Claim(claim.Key, claim.Value));
            }
        }

        // Create a ClaimsIdentity and set it on the HttpContext
        var identity = new ClaimsIdentity(claims, "SasToken");
        context.User = new ClaimsPrincipal(identity);

        // Call the next middleware in the pipeline
        await _next(context);
    }
}