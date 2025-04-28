namespace N2.Security.Sas
{
    public class SasTokenValidationResult : ISasTokenValidationResult
    {
        public SasTokenValidationResult()
        {
        }

        public static SasTokenValidationResult Accepted(string[] resourceRequest)
        {
            return new SasTokenValidationResult(true, resourceRequest, TokenResponseCode.TokenAccepted);
        }

        public static SasTokenValidationResult NotAccepted(string[] resourceRequest)
        {
            return new SasTokenValidationResult(false, resourceRequest, TokenResponseCode.NotAccepted);
        }

        public static SasTokenValidationResult Failed(string[] resourceRequest, TokenResponseCode responseCode)
        {
            return new SasTokenValidationResult(false, resourceRequest, responseCode);
        }

        public SasTokenValidationResult(bool success, string[] resourceRequest, TokenResponseCode code)
        {
            Success = success;
            Resource = string.Join(',', resourceRequest);
            TokenResponseCode = code;
        }

        public bool Success { get; private set; }
        public TokenResponseCode TokenResponseCode { get; private set; }
        public string Resource { get; private set; }

        /// <summary>
        /// Performs an implicit conversion from <see cref="SasTokenValidationResult" /> to <see cref="System.Boolean" />.
        /// </summary>
        /// <param name="r">The r.</param>
        /// <returns>The result of the conversion.</returns>
        /// <remarks>no comments</remarks>
        public static implicit operator bool(SasTokenValidationResult r)
        {
            if (r == null)
            {
                return false;
            }

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