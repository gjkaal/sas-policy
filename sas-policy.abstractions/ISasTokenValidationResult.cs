namespace N2.Security.Sas
{
    /// <summary>
    /// Interface for SAS token validation result
    /// </summary>
    public interface ISasTokenValidationResult
    {
        bool Success { get; }
        TokenResponseCode TokenResponseCode { get; }

        /// <summary>
        /// The token that was validated, usually the rights requested.
        /// </summary>
        string Resource { get; }

    }

}