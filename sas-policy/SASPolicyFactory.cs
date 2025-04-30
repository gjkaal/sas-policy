using System;
using System.Text.RegularExpressions;

namespace N2.Security.Sas
{
    public static class SASPolicyFactory
    {
        public static ISasPolicy CreatePolicy(string skn, string sharedSecret, int timeoutInSeconds, HashType hashType = HashType.Sha256)
        {
            if (timeoutInSeconds < 10)
            {
                throw new ArgumentOutOfRangeException(nameof(timeoutInSeconds), "A timeout should be at least 10 s");
            }

            return new SASPolicy
            {
                Skn = skn,
                Key = sharedSecret,
                SharedResourceExpression = ".*",
                AllowedPermissions = [],
                HashType = hashType,
                UseNonce = false,
                TokenTimeOut = timeoutInSeconds,
                TypeName = "SimplePolicy"
            };
        }

        public static ISasPolicy WithPermissions(this ISasPolicy policy, string[] resourcePermissions)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }

            // Join existing permissions with new permissions
            var permissions = new string[policy.AllowedPermissions.Length + resourcePermissions.Length];
            Array.Copy(policy.AllowedPermissions, permissions, policy.AllowedPermissions.Length);
            Array.Copy(resourcePermissions, 0, permissions, policy.AllowedPermissions.Length, resourcePermissions.Length);
            policy.AllowedPermissions = permissions;
            return policy;
        }

        public static ISasPolicy WithMatch(this ISasPolicy policy, string match)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }
            if (string.IsNullOrEmpty(match))
            {
                return policy;
            }
            // check if the match is a valid regex
            var regex = new Regex(match, RegexOptions.Compiled);
            policy.SharedResourceExpression = match;
            return policy;
        }

        public static ISasPolicy WithHash(this ISasPolicy policy, HashType hashType)
        {
            if (policy == null)
            {
                throw new ArgumentNullException(nameof(policy));
            }
            if (hashType == HashType.None)
            {
                throw new ArgumentOutOfRangeException(nameof(hashType), "HashType cannot be None");
            }
            // check if the match is a valid regex
            policy.HashType = hashType;
            return policy;
        }
    }
}