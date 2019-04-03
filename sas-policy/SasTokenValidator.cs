using Microsoft.Extensions.Caching.Memory;
using System;
using System.Collections.Generic;

namespace Nice2Experience.SasPolicy
{

    public class SasTokenValidator : ISasTokenValidator
    {
        public const int NonceTimeOutInMinutes = 10;
        public const int DefaultTokenTimeoutInSeconds = 60;
        private readonly IMemoryCache _memoryCache;
        private readonly string _sharedSecret;
        private readonly HashType _hashType;
        private const string DefaultSecret = "thisisthesecretkey";

        public SasTokenValidator()
        {
            _hashType = HashType.Sha256;
            _sharedSecret = DefaultSecret;
        }

        public SasTokenValidator(IMemoryCache memoryCache) : this(HashType.Sha256, DefaultSecret)
        {
            _memoryCache = memoryCache;
        }

        public SasTokenValidator(HashType hashType, string sharedSecret, IMemoryCache memoryCache) : this(hashType, sharedSecret)
        {
            _memoryCache = memoryCache;
        }

        public SasTokenValidator(HashType hashType, string sharedSecret)
        {
            _sharedSecret = sharedSecret;
            _hashType = hashType;
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

        public void ValidateAndThrowException(string queryString, string sharedSecret, HashType hashType)
        {
            var token = SasTokenFactory.Parse(queryString);
            var r = Validate(token, sharedSecret, hashType);
            // TODO : Get description from metadata
            if (!r.Success) throw new ArgumentOutOfRangeException(r.TokenResponseCode.ToString());
        }

        #region overloads
        public ISasTokenValidationResult Validate(ISasTokenParameters token)
        {
            return ExecuteValidation(token, _sharedSecret, !string.IsNullOrEmpty(token.Nonce), _hashType, token.AdditionalValues?.Keys ?? null, false);
        }

        public ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType)
        {
            return ExecuteValidation(token, sharedSecret, useNonce, hashType, token.AdditionalValues?.Keys ?? null, false);
        }

        public ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType, IEnumerable<string> additionalKeys)
        {
            return ExecuteValidation(token, sharedSecret, useNonce, hashType, additionalKeys, false);
        }

        public ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, HashType hashType)
        {
            return ExecuteValidation(token, sharedSecret, false, hashType, token.AdditionalValues?.Keys ?? null, false);
        }

        public ISasTokenValidationResult Validate(string queryString)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, _sharedSecret, false, _hashType, null, false);
        }

        public ISasTokenValidationResult Validate(string queryString, IEnumerable<string> additionalKeys)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, _sharedSecret, false, _hashType, additionalKeys, false);
        }

        public ISasTokenValidationResult Validate(string queryString, bool ignoreTimeOut)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, _sharedSecret, false, _hashType, null, ignoreTimeOut);
        }

        public ISasTokenValidationResult Validate(string queryString, string sharedSecret)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, sharedSecret, false, _hashType, null, false);
        }

        public ISasTokenValidationResult Validate(string queryString, string sharedSecret, HashType hashType)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, sharedSecret, false, hashType, null, false);
        }

        public ISasTokenValidationResult Validate(string queryString, string sharedSecret, IEnumerable<string> additionalKeys)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, sharedSecret, false, _hashType, additionalKeys, true);
        }

        public ISasTokenValidationResult Validate(string queryString, string sharedSecret, HashType hashType, IEnumerable<string> additionalKeys)
        {
            var token = SasTokenFactory.Parse(queryString);
            return ExecuteValidation(token, sharedSecret, false, hashType, additionalKeys, true);
        }
        #endregion
    }
}
