namespace Nice2Experience.Security.Sas
{
    public class SasTokenValidationResult : ISasTokenValidationResult
    {
        public SasTokenValidationResult()
        {
        }

        public SasTokenValidationResult(string resource)
        {
            Resource = resource;
            Success = true;
            TokenResponseCode = TokenResponseCode.TokenAccepted;
        }

        public SasTokenValidationResult(bool success, string resource)
        {
            Success = success;
            Resource = resource;
            TokenResponseCode = success ? TokenResponseCode.TokenAccepted : TokenResponseCode.NotAccepted;
        }

        public SasTokenValidationResult(bool success, string resource, TokenResponseCode code)
        {
            Success = success;
            Resource = resource;
            TokenResponseCode = code;
        }

        public bool Success { get; set; }
        public TokenResponseCode TokenResponseCode { get; set; }
        public string Resource { get; set; }

        /// <summary>
        /// Performs an implicit conversion from <see cref="SasTokenValidationResult" /> to <see cref="System.Boolean" />.
        /// </summary>
        /// <param name="r">The r.</param>
        /// <returns>The result of the conversion.</returns>
        /// <remarks>no comments</remarks>
        public static implicit operator bool(SasTokenValidationResult r)
        {
            if (r == null) return false;
            return r.Success;
        }

        /// <summary>
        /// Performs an implicit conversion from <see cref="System.Boolean" /> to <see cref="SasTokenValidationResult" />.
        /// </summary>
        /// <param name="success">if set to <c>true</c> [success].</param>
        /// <returns>The result of the conversion.</returns>
        /// <remarks>no comments</remarks>
        public static implicit operator SasTokenValidationResult(bool success)
        {
            return new SasTokenValidationResult { Success = success };
        }
    }
}