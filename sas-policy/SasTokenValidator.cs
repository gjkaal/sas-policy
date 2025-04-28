using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Memory;

namespace N2.Security.Sas
{
    public class SasTokenValidator : ISasTokenValidator
    {
        private readonly IMemoryCache _memoryCache;
        private readonly ISasPolicyRepository _sasPolicyRepository;
        public const int DefaulNonceTimeOutInMinutes = 5;
        private const string DefaultSecret = "N2-secret";

        private int _nonceTimeOutInMinutes = DefaulNonceTimeOutInMinutes;

        public int NonceTimeOutInMinutes
        {
            get => _nonceTimeOutInMinutes;
            set => _nonceTimeOutInMinutes = value < 1 ? DefaulNonceTimeOutInMinutes : value;
        }

        public SasTokenValidator(ISasPolicyRepository sasPolicyRepository)
        {
            _sasPolicyRepository = sasPolicyRepository;
        }

        public SasTokenValidator(
            ISasPolicyRepository sasPolicyRepository,
            IMemoryCache memoryCache) : this(sasPolicyRepository)
        {
            _memoryCache = memoryCache;
        }

        /// <summary>
        /// Validate a token using the provided secret and hashtype
        /// </summary>
        /// <param name="resourcePath">
        /// Resource path to be validated
        /// </param>
        /// <param name="token">
        /// Token to be validated
        /// </param>
        /// <param name="sharedSecret">
        /// The passphrase used to create the token's signature
        /// </param>
        /// <param name="useNonce">
        /// If true, the nonce is checked against previous validations, preventing resends
        /// </param>
        /// <param name="hashType">
        /// The hashing type used to generate the signature
        /// </param>
        /// <param name="additionalKeys">
        /// If true, the signature expects additional keys from the token
        /// </param>
        /// <param name="ignoreTimeOut">
        /// if true, ignore the timestamp when validating.
        /// </param>
        /// <returns>
        /// </returns>
        private SasTokenValidationResult ExecuteValidation(
            Uri resourcePath,
            string resourceMatch,
            ISasTokenParameters token,
            string[] allowedResources,
            string sharedSecret,
            bool useNonce,
            HashType hashType,
            IEnumerable<string> additionalKeys,
            bool ignoreTimeOut)
        {
            if (!Regex.IsMatch(resourcePath.ToString(), resourceMatch.ToString()))
            {
                return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.SharedResourceExpressionFailed);
            }

            // check permissions, if provided
            if (allowedResources.Length > 0 && token.SharedResource.Length > 0)
            {
                if (!CheckPermissions(allowedResources, token.SharedResource))
                {
                    return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.PolicyFailed);
                }
            }

            // check if the signing key is valid
            if (string.IsNullOrEmpty(sharedSecret))
            {
                return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.InvalidSigningKey);
            }

            var epochCurrent = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var expiryTest = (int)epochCurrent.TotalSeconds;
            if (!ignoreTimeOut && token.Expiry < expiryTest)
            {
                return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.TokenExpired);
            }

            if (useNonce && _memoryCache != null)
            {
                if (string.IsNullOrEmpty(token.Nonce))
                {
                    return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.NonceIsRequired);
                }

                if (TryGetValueFromcache(token.Nonce))
                {
                    return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.ResendNotAllowed);
                }

                SetInCache(token.Nonce);
            }

            var validateSignature = token.CalcSignature(sharedSecret, useNonce, hashType, additionalKeys);
            if (token.Signature != validateSignature)
            {
                return SasTokenValidationResult.Failed(token.SharedResource, TokenResponseCode.TokenTampered);
            }

            return SasTokenValidationResult.Accepted(token.SharedResource);
        }

        private static bool CheckPermissions(string[] resourceRequest, string[] permissions)
        {
            foreach (var permission in permissions)
            {
                if (!Array.Exists(resourceRequest, element => element == permission))
                {
                    return false;
                }
            }
            return true;
        }

        private void SetInCache(string nonce)
        {
            if (_memoryCache == null)
            {
                return;
            }

            var policy = new MemoryCacheEntryOptions
            {
                Priority = CacheItemPriority.Normal,
                AbsoluteExpiration = DateTimeOffset.Now.AddMinutes(NonceTimeOutInMinutes)
            };
            _memoryCache.Set(nonce, nonce, policy);
        }

        private bool TryGetValueFromcache(string nonce)
        {
            if (_memoryCache == null)
            {
                return false;
            }

            return _memoryCache.TryGetValue(nonce, out _);
        }

        public async Task ValidateAndThrowException(Uri resourcePath, string queryString)
        {
            var token = SasTokenFactory.Parse(queryString);
            var r = await Validate(resourcePath, token);

            if (!r.Success)
            {
                throw new ArgumentOutOfRangeException(r.TokenResponseCode.Description());
            }
        }

        #region overloads

        public Task<ISasTokenValidationResult> Validate(Uri resourcePath, string queryString)
        {
            var token = SasTokenFactory.Parse(queryString);
            return Validate(resourcePath, token);
        }

        public Task<ISasTokenValidationResult> Validate(Uri resourcePath, string queryString, bool ignoreTimeOut)
        {
            var token = SasTokenFactory.Parse(queryString);
            return Validate(resourcePath, token, ignoreTimeOut);
        }

        public Task<ISasTokenValidationResult> Validate(Uri resourcePath, ISasTokenParameters token)
        {
            return Validate(resourcePath, token, false);
        }

        public async Task<ISasTokenValidationResult> Validate(Uri resourcePath, ISasTokenParameters token, bool ignoreTimeOut)
        {
            var p = await _sasPolicyRepository.GetPolicy(token.SigningKeyName);
            if (p == null)
            {
                return new SasTokenValidationResult(false, token.SharedResource, TokenResponseCode.PolicyNotFound);
            }

            return ExecuteValidation(
                resourcePath,
                p.SharedResourceExpression,
                token,
                p.ResourceRequest,
                p.Key,
                p.UseNonce,
                p.HashType,
                p.AdditionalKeys,
                ignoreTimeOut);
        }

        #endregion overloads
    }
}