using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;

namespace Nice2Experience.Security.Sas
{
    public class SasTokenValidator : ISasTokenValidator
    {
        public const int NonceTimeOutInMinutes = 10;
        public const int DefaultTokenTimeoutInSeconds = 60;
        private readonly IMemoryCache _memoryCache;
        private readonly Dictionary<string, ISasPolicy> policies;
        private const string DefaultSecret = "nice2experience-secret";

        public SasTokenValidator()
        {
            policies = new Dictionary<string, ISasPolicy>();
            // add default policy
            var policy = SASPolicyFactory.CreatePolicy("sk", DefaultSecret, 60);
            policies.Add("testKey", policy);
        }

        public SasTokenValidator(ISasPolicy policy) : this()
        {
            policies.Add(policy.Skn, policy);
        }

        public SasTokenValidator(IMemoryCache memoryCache) : this()
        {
            _memoryCache = memoryCache;
        }

        public SasTokenValidator(IMemoryCache memoryCache, HashType hashType, string keyName, string sharedSecret) : this(hashType, keyName, sharedSecret)
        {
            _memoryCache = memoryCache;
        }

        public SasTokenValidator(HashType hashType, string keyName, string sharedSecret) : this()
        {
            var policy = SASPolicyFactory.CreatePolicy(keyName, sharedSecret, 60);
            policies.Add("testKey", policy);
        }

        /// <summary>
        /// Validate a token using the provided secret and hashtype
        /// </summary>
        /// <param name="token">Token to be validated</param>
        /// <param name="sharedSecret">The passphrase used to create the token's signature</param>
        /// <param name="useNonce">If true, the nonce is checked against previous validations, preventing resends</param>
        /// <param name="hashType">The hashing type used to generate the signature</param>
        /// <param name="additionalKeys">If true, the signature expects additional keys from the token</param>
        /// <param name="ignoreTimeOut">if true, ignore the timestamp when validating.</param>
        /// <returns></returns>
        private ISasTokenValidationResult ExecuteValidation(
            ISasTokenParameters token,
            string sharedSecret,
            bool useNonce,
            HashType hashType,
            IEnumerable<string> additionalKeys,
            bool ignoreTimeOut)
        {
            if (string.IsNullOrEmpty(sharedSecret))
                return new SasTokenValidationResult
                {
                    Success = false,
                    TokenResponseCode = TokenResponseCode.InvalidSigningKey
                };

            var epochCurrent = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var expiryTest = (int)epochCurrent.TotalSeconds;
            if (!ignoreTimeOut && token.Expiry < expiryTest)
                return new SasTokenValidationResult
                {
                    TokenResponseCode = TokenResponseCode.TokenExpired,
                    Success = false
                };
            if (useNonce && _memoryCache != null)
            {
                if (string.IsNullOrEmpty(token.Nonce))
                    return new SasTokenValidationResult
                    {
                        TokenResponseCode = TokenResponseCode.NonceIsRequired,
                        Success = false
                    };

                if (TryGetValueFromcache(token.Nonce))
                    return new SasTokenValidationResult
                    {
                        TokenResponseCode = TokenResponseCode.ResendNotAllowed,
                        Success = false
                    };

                SetInCache(token.Nonce);
            }

            var validateSignature = token.CalcSignature(sharedSecret, useNonce, hashType, additionalKeys);
            if (token.Signature != validateSignature)
                return new SasTokenValidationResult
                {
                    TokenResponseCode = TokenResponseCode.TokenTampered,
                    Success = false
                };
            return new SasTokenValidationResult
            {
                TokenResponseCode = TokenResponseCode.TokenAccepted,
                Resource = token.SharedResource,
                Success = true
            };
        }

        private void SetInCache(string nonce)
        {
            if (_memoryCache == null) return;
            var policy = new MemoryCacheEntryOptions
            {
                Priority = CacheItemPriority.Normal,
                AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(NonceTimeOutInMinutes)
            };
            _memoryCache.Set(nonce, nonce, policy);
        }

        private bool TryGetValueFromcache(string nonce)
        {
            if (_memoryCache == null) return false;
            return _memoryCache.TryGetValue(nonce, out _);
        }

        public void ValidateAndThrowException(string queryString)
        {
            var token = SasTokenFactory.Parse(queryString);
            var r = Validate(token);
            // TODO : Get description from metadata
            if (!r.Success) throw new ArgumentOutOfRangeException(r.TokenResponseCode.ToString());
        }

        #region overloads

        public ISasTokenValidationResult Validate(string queryString)
        {
            var token = SasTokenFactory.Parse(queryString);
            return Validate(token);
        }

        public ISasTokenValidationResult Validate(string queryString, bool ignoreTimeOut)
        {
            var token = SasTokenFactory.Parse(queryString);
            return Validate(token, ignoreTimeOut);
        }

        public ISasTokenValidationResult Validate(ISasTokenParameters token)
        {
            return Validate(token, false);
        }

        public ISasTokenValidationResult Validate(ISasTokenParameters token, bool ignoreTimeOut)
        {
            if (!policies.ContainsKey(token.SigningKeyName))
            {
                return new SasTokenValidationResult(false, token.SharedResource, TokenResponseCode.PolicyFailed);
            }
            var p = policies[token.SigningKeyName];
            return ExecuteValidation(token, p.Key, p.UseNonce, p.HashType, p.AdditionalKeys, ignoreTimeOut);
        }

        #endregion
    }
}
