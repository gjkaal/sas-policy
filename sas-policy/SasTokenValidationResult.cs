using System;

using Microsoft.Extensions.Primitives;

namespace N2.Security.Sas
{
    public class SasTokenValidationResult : ISasTokenValidationResult
    {
        public SasTokenValidationResult()
        {
            Resource = string.Empty;
        }

        public static SasTokenValidationResult Accepted(Uri resourceRequest, StringValues permissions)
        {
            return new SasTokenValidationResult(true, resourceRequest, permissions, TokenResponseCode.TokenAccepted);
        }

        public static SasTokenValidationResult NotAccepted(Uri resourceRequest)
        {
            return new SasTokenValidationResult(false, resourceRequest, string.Empty, TokenResponseCode.NotAccepted);
        }

        public static SasTokenValidationResult Failed(Uri resourceRequest, TokenResponseCode responseCode)
        {
            return new SasTokenValidationResult(false, resourceRequest, string.Empty, responseCode);
        }

        private SasTokenValidationResult(bool success, Uri resourceRequest, StringValues permissions, TokenResponseCode code)
        {
            Success = success;
            Resource = resourceRequest.ToString();
            TokenResponseCode = code;
            Permissions = permissions.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);
        }

        public bool Success { get; private set; }
        public TokenResponseCode TokenResponseCode { get; private set; }
        public string Resource { get; private set; }
        public string[] Permissions { get; private set; } = Array.Empty<string>();

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