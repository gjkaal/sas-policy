using System.ComponentModel;

namespace Nice2Experience.Security.Sas
{
    public enum TokenResponseCode
    {
        [Description("Token not accepted")]
        NotAccepted = 0,
        [Description("Token accepted")]
        TokenAccepted = 1,
        [Description("The token validator needs a caching provider to validate this token, but no caching provider is available")]
        ValidatorNotInitialized = 2,
        [Description("Token expired")]
        TokenExpiredMessage = 3,
        [Description("Nonce is required")]
        NonceIsRequired = 4,
        [Description("Resend not allowed")]
        ResendNotAllowed = 5,
        [Description("Token tampered")]
        TokenTampered = 6,
        [Description("Invalid signing key")]
        InvalidSigningKey = 7,
        [Description("Token is expired")]
        TokenExpired = 8,
        [Description("Shared resource expression failed to match for {0}")]
        SharedResourceExpressionFailed = 9,
        [Description("Policy permission failed {0}")]
        PolicyFailed = 10

    }
}