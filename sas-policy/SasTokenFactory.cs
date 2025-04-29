using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.AspNetCore.Http;


namespace N2.Security.Sas
{
    /// <summary>
    ///     Parses or creates SAS-tokens
    /// </summary>
    public static class SasTokenFactory
    {
        public const int DefaultTokenTimeOutInSeconds = 120;

        private static readonly Random Random = new();

        // skn = signing key name
        // sr = shared resource (requested access)
        // se = expiry time (unix time)
        // sig = signature over the sr, skn, nonce and time

        private static readonly string[] sourceArray = ["skn", "sr", "se", "sig", "nonce"];

        public static SasTokenParameters FromHeaders(IHeaderDictionary headers)
        {
            var additionalList = new Dictionary<string, string>();
            foreach (var kvp in
                headers.Where(x =>
                    x.Key.StartsWith("sas-", StringComparison.InvariantCultureIgnoreCase)
                    && !sourceArray.Contains(x.Key)))
            {
                additionalList.Add(kvp.Key, kvp.Value);
            }

            var sr = headers["sr"];
            var srList = sr.ToArray();
            var token = new SasTokenParameters
            {
                SigningKeyName = headers["skn"],
                SharedResource = srList,
                Expiry = GetInt(headers["se"]),
                Signature = headers["sig"],
                Nonce = headers["nonce"],
                AdditionalValues = additionalList
            };
            token.Invalid = string.IsNullOrEmpty(token.SigningKeyName)
                || token.SharedResource.Length == 0
                || string.IsNullOrEmpty(token.Signature)
                || token.Expiry <= 0;
            return token;
        }

        public static SasTokenParameters Parse(IList<KeyValuePair<string, string>> args)
        {
            var additionalList = new Dictionary<string, string>();
            foreach (var kvp in args.Where(x => !sourceArray.Contains(x.Key)))
            {
                additionalList.Add(kvp.Key, kvp.Value);
            }

            var sr = args.First(q => q.Key == "sr").Value;
            var srList = sr.Split([','], StringSplitOptions.RemoveEmptyEntries);

            var token = new SasTokenParameters
            {
                SigningKeyName = args.FirstOrDefault(q => q.Key == "skn").Value,
                SharedResource = srList,
                Expiry = GetInt(args.FirstOrDefault(q => q.Key == "se").Value),
                Signature = args.FirstOrDefault(q => q.Key == "sig").Value,
                Nonce = args.FirstOrDefault(q => q.Key == "nonce").Value,
                AdditionalValues = additionalList
            };
            token.Invalid = string.IsNullOrEmpty(token.SigningKeyName)
                || token.SharedResource.Length == 0
                || string.IsNullOrEmpty(token.Signature)
                || token.Expiry <= 0;
            return token;
        }

        public static SasTokenParameters Parse(string queryString)
        {
            if (string.IsNullOrEmpty(queryString))
            {
                return new SasTokenParameters
                {
                    Invalid = true
                };
            }

            if (queryString[0] == '?')
            {
                queryString = queryString[1..];
            }

            return Parse(queryString.GetDictionary('&', '='));
        }

        /// <summary>
        ///     parse keyvaluelist argument to a SasToken
        /// </summary>
        public static SasTokenParameters Parse(IDictionary<string, string> args)
        {
            var kvp = args.Select(x => new KeyValuePair<string, string>(x.Key, x.Value));
            return Parse([.. kvp]);
        }

        private static int GetInt(string value)
        {
            if (int.TryParse(value, out var result))
            {
                return result;
            }

            return 0;
        }

        ///// <summary>
        ///// Create signed sastoken using a policy
        ///// </summary>
        public static SasTokenParameters Create(string[] sharedResourceRequest, IDictionary<string, string> additionalValues, ISasPolicy policy)
        {
            return ExecuteCreate(sharedResourceRequest, policy.TokenTimeOut, policy.Skn, additionalValues, policy.UseNonce, policy.HashType, policy.Key);
        }

        ///// <summary>
        ///// Create signed sastoken using a policy
        ///// </summary>
        public static SasTokenParameters Create(string[] sharedResourceRequest, ISasPolicy policy)
        {
            return ExecuteCreate(sharedResourceRequest, policy.TokenTimeOut, policy.Skn, null, policy.UseNonce, policy.HashType, policy.Key);
        }

        /// <summary>
        ///     Create signed sastoken with no additional values
        /// </summary>
        public static SasTokenParameters Create(string[] sharedResourceRequest, ISasPolicy policy, bool calculateSignature)
        {
            var token = ExecuteCreate(
                sharedResourceRequest,
                policy.TokenTimeOut,
                policy.Skn,
                null,
                policy.UseNonce,
                policy.HashType,
                calculateSignature ? policy.Key : string.Empty
                );
            return token;
        }

        public static SasTokenParameters Create(string[] sharedResourceRequest, HashType hashType, string signingKeyName, string sharedSecret)
        {
            return ExecuteCreate(sharedResourceRequest, DefaultTokenTimeOutInSeconds, signingKeyName, null, false, hashType, sharedSecret);
        }

        public static SasTokenParameters Create(string[] sharedResourceRequest, HashType hashType, string signingKeyName, string sharedSecret, bool useNonce)
        {
            return ExecuteCreate(sharedResourceRequest, DefaultTokenTimeOutInSeconds, signingKeyName, null, useNonce, hashType, sharedSecret);
        }

        public static SasTokenParameters Create(string[] sharedResourceRequest, HashType hashType, string signingKeyName, string sharedSecret, int timeoutInSeconds)
        {
            return ExecuteCreate(sharedResourceRequest, timeoutInSeconds, signingKeyName, null, false, hashType, sharedSecret);
        }

        public static SasTokenParameters Create(string[] sharedResourceRequest, HashType hashType, string signingKeyName, string sharedSecret, bool useNonce, int timeoutInSeconds)
        {
            return ExecuteCreate(sharedResourceRequest, timeoutInSeconds, signingKeyName, null, useNonce, hashType, sharedSecret);
        }


        /// <summary>
        ///     Create signed sastoken
        /// </summary>
        /// <param name="sharedResourceRequest">Requested access to the shared resource.</param>
        /// <param name="timeoutInSeconds">The timeout for the token in seconds.</param>
        /// <param name="signingKey">The signing key.</param>
        /// <param name="additionalValues">The additional values that should be included.</param>
        /// <param name="useNonce">if set to <c>true</c> then use the nonce in the signature.</param>
        /// <param name="hashType">Type of the hash.</param>
        /// <param name="sharedSecret">if set to a valid string then the calculation is executed immediately.</param>
        /// <returns>SASToken.</returns>
        public static SasTokenParameters Create(
            string[] sharedResourceRequest,
            HashType hashType,
            string signingKeyName,
            string sharedSecret,
            bool useNonce,
            int timeoutInSeconds,
            IDictionary<string, string> additionalValues)
        {
            return ExecuteCreate(sharedResourceRequest, timeoutInSeconds, signingKeyName, additionalValues, useNonce, hashType, sharedSecret);
        }


        /// <summary>
        ///     Create signed sastoken
        /// </summary>
        /// <param name="sharedResourceRequest">Requested access to the shared resource.</param>
        /// <param name="timeoutInSeconds">The timeout for the token in seconds.</param>
        /// <param name="signingKeyName">The name for the signing key.</param>
        /// <param name="additionalValues">The additional values that should be included.</param>
        /// <param name="useNonce">if set to <c>true</c> then use the nonce in the signature.</param>
        /// <param name="hashType">Type of the hash.</param>
        /// <param name="sharedSecret">if set to a valid string then the calculation is executed immediately.</param>
        /// <param name="includeAdditionalValues">if set to <c>true</c> then use the additional values in the signature.</param>
        /// <param name="includeAdditionalKeys">if set to <c>true</c> then use the additional keys in the signature.</param>
        /// <returns>SASToken.</returns>
        private static SasTokenParameters ExecuteCreate(
            string[] sharedResourceRequest,
            int timeoutInSeconds,
            string signingKeyName,
            IDictionary<string, string> additionalValues,
            bool useNonce,
            HashType hashType,
            string sharedSecret)
        {
            if (string.IsNullOrEmpty(sharedSecret))
            {
                throw new ArgumentNullException(nameof(sharedSecret), "Invalid signing key");
            }
            var epochCurrent = DateTime.UtcNow - new DateTime(1970, 1, 1);
            var expiry = (int)epochCurrent.TotalSeconds + timeoutInSeconds;

            var sasToken = new SasTokenParameters
            {
                SharedResource = sharedResourceRequest,
                Expiry = expiry,
                SigningKeyName = signingKeyName,
                AdditionalValues = additionalValues,
                Nonce = ""
            };
            if (useNonce)
            {
                sasToken.Nonce = CreateNewNonce(12);
            }
            sasToken.Signature = sasToken.CalcSignature(
              sharedSecret,
              useNonce,
              hashType,
              additionalValues?.Keys);
            return sasToken;
        }



        private static string CreateNewNonce(int len)
        {
            const string nOnceData = "CrossPointABCdefgHIJklMNOPqRstUVWWqqCROSSPOINT1234567891122QuickBrownFoxJumpsOverTheLazyDog";
            var nOnceLen = nOnceData.Length;
            if (len < 6)
            {
                throw new ArgumentOutOfRangeException(nameof(len), "Parameter len should contain an integer with a value of 6 or larger");
            }

            var nonce = new char[len];
            for (var x = 0; x < len; x++)
            {
                nonce[x] = nOnceData[Random.Next(0, nOnceLen)];
            }

            return new string(nonce);
        }
    }
}
