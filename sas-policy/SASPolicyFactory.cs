using System;
using System.Text.RegularExpressions;

namespace Nice2Experience.SasPolicy
{
    public static class SASPolicyFactory
    {
        /// <summary>
        ///     Validates permissions of the specified keyName for the specified resource
        /// </summary>
        /// <param name="resource">The resource</param>
        /// <param name="permissions">The permissions.</param>
        /// <returns>True, if resource can be accessed otherwise false</returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public static ISasTokenValidationResult CheckPolicy(this ISasPolicy sasPolicy, string resource, Permissions permissions)
        {
            // match resource
            if (!Regex.IsMatch(resource, sasPolicy.SharedResourceExpression))
                return new SasTokenValidationResult
                {
                    Success = false,
                    TokenResponseCode = TokenResponseCode.SharedResourceExpressionFailed
                };

            // chck permissions, if provided
            if (sasPolicy.Permissions != Permissions.None)
                if ((permissions & sasPolicy.Permissions) != permissions)
                    return new SasTokenValidationResult
                    {
                        Success = false,
                        TokenResponseCode = TokenResponseCode.PolicyFailed
                    };
            return new SasTokenValidationResult(resource);
        }

        public static ISasPolicy CreatePolicy(string skn, string sharedSecret, int timeoutInSeconds)
        {
            if (timeoutInSeconds < 10) throw new ArgumentOutOfRangeException(nameof(timeoutInSeconds), "A timeout should be at least 10 s");
            return new SASPolicy
            {
                Skn = skn,
                Key = sharedSecret,
                SharedResourceExpression = ".*",
                Permissions = Permissions.None,
                HashType = HashType.Sha256,
                UseNonce = false,
                TokenTimeOut = timeoutInSeconds,
                TypeName = "SimplePolicy"
            };
        }
    }

}
