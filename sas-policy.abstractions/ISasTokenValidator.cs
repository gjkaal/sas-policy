namespace N2.Security.Sas
{
    public interface ISasTokenValidator
    {
        Task<ISasTokenValidationResult> Validate(Uri resourcePath, ISasTokenParameters token);
        Task<ISasTokenValidationResult> Validate(Uri resourcePath, ISasTokenParameters token, bool ignoreTimeout);
        Task<ISasTokenValidationResult> Validate(Uri resourcePath, string queryString);
        Task<ISasTokenValidationResult> Validate(Uri resourcePath, string queryString, bool ignoreTimeout);
        Task ValidateAndThrowException(Uri resourcePath, string queryString);
    }
}