namespace N2.Security.Sas
{
    /// <summary>
    /// Interface for SAS token validation result
    /// </summary>
    public interface ISasTokenValidationResult
    {
        /// <summary>
        /// True if the token was validated successfully.
        /// </summary>
        bool Success { get; }

        /// <summary>
        /// The response code of the token validation.
        /// </summary>
        TokenResponseCode TokenResponseCode { get; }

        /// <summary>
        /// The permissions that were validated.
        /// </summary>
        string[] Permissions { get; }

        /// <summary>
        /// The token that was validated, usually the rights requested.
        /// </summary>
        string Resource { get; }

    }

}