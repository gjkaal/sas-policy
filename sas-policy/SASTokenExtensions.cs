using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Nice2Experience.SasPolicy
{
    public static class SASTokenExtensions
    {

        private const string SharedKeyTooShortMessage = "Shared secret does not comply to policies (too short). Check if the KeyName and Shared Secret are not switched";

        /// <summary>
        ///     returns a string representation of this token for use in a URL
        /// </summary>
        public static string ToQueryString(this ISasTokenParameters token)
        {
            var components = new List<string>();
            if (!string.IsNullOrEmpty(token.SharedResource)) components.Add($"sr={WebUtility.UrlEncode(token.SharedResource)}");
            if (!string.IsNullOrEmpty(token.Signature)) components.Add($"sig={WebUtility.UrlEncode(token.Signature)}");
            if (token.Expiry > 0) components.Add($"se={token.Expiry}");
            if (!string.IsNullOrEmpty(token.Nonce)) components.Add($"nonce={WebUtility.UrlEncode(token.Nonce)}");
            if (!string.IsNullOrEmpty(token.SigningKey)) components.Add($"skn={WebUtility.UrlEncode(token.SigningKey)}");
            if (token.AdditionalValues != null)
            {
                foreach (var kvp in token.AdditionalValues)
                {
                    components.Add($"{kvp.Key}={WebUtility.UrlEncode(kvp.Value)}");
                }
            }
            return string.Join("&", components);
        }

        public static string CalcSignature(this ISasTokenParameters token, string sharedSecret, HashType hashType)
        {
            return CalcSignature(token, sharedSecret, false, hashType, null);
        }

        public static ISasTokenValidationResult ValidateSigningKeyPolicies(string sharedSecret)
        {
            if (sharedSecret.Length < 20) return new SasTokenValidationResult(false, SharedKeyTooShortMessage);
            return new SasTokenValidationResult(true, string.Empty);
        }

        /// <summary>
        ///     calculate the signature of the sastoken
        /// </summary>
        public static string CalcSignature(this ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType)
        {
            return CalcSignature(token, sharedSecret, useNonce, hashType, null);
        }

        /// <summary>
        ///     calculate the signature of the sastoken
        /// </summary>
        public static string CalcSignature(this ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType, IEnumerable<string> additionalKeys)
        {
            // to be safe, the sharedsecret should contain at least 20 characters.
            // this also limits the number of erroneous switch of the key name and shared secret
            var keyPolicyCheck = ValidateSigningKeyPolicies(sharedSecret);
            if (!keyPolicyCheck.Success) throw new ArgumentOutOfRangeException(nameof(sharedSecret), keyPolicyCheck.TokenResponseCode.ToString());

            var stringToSign = WebUtility.UrlEncode(token.SharedResource) + "\n";

            if (additionalKeys != null)
            {
                foreach (var key in additionalKeys)
                {
                    var kvp = token.AdditionalValues.FirstOrDefault(q => q.Key == key);
                    if (kvp.Key == null) throw new ArgumentException($"Value is missing : {key}");
                    stringToSign += $"{kvp.Key}={WebUtility.UrlEncode(kvp.Value)}\n";
                }
            }
            if (useNonce) stringToSign += $"{WebUtility.UrlEncode(token.Nonce)}\n";
            stringToSign += token.Expiry;
            return CalculateHash(sharedSecret, hashType, stringToSign);
        }

        public static string CalculateHash(string sharedSecret, HashType hashType, string stringToSign)
        {
            string signature;
            switch (hashType)
            {
                default:
                    throw new NotSupportedException($"Hashing using {hashType.ToString()} is not supported");
                case HashType.MD5:
                    using (var hmac = MD5.Create())
                    {
                        var bytes = hmac.ComputeHash(Encoding.ASCII.GetBytes(stringToSign + '\n' + sharedSecret));
                        signature = BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
                    }

                    break;
                case HashType.Sha1:
                    using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }

                    break;
                case HashType.Sha256:
                    // This should be the default. Use other methods only, of the client system
                    // cannot create SHA256 hashes
                    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }

                    break;
            }

            return signature;
        }

        public static T GetValue<T>(this IDictionary<string, string> items, string key)
        {
            object result;
            var type = typeof(T);
            var item = default(T);
            if (!items.ContainsKey(key)) return default(T);
            var value = items[key];
            if (item is Guid)
            {
                result = Guid.Parse(value);
            }
            else
            {
                result = Convert.ChangeType(value, type);
            }
            return (T)result;
        }

        public static IDictionary<string, string> GetDictionary(this string queryString, char separator, char assignment)
        {
            var result = new Dictionary<string, string>();

            if (string.IsNullOrEmpty(queryString)) return result;

            var items = queryString.Split(separator);
            foreach (var item in items)
            {
                var itemValue = item.Trim();
                if (!string.IsNullOrWhiteSpace(itemValue))
                {
                    var element = itemValue.Split(assignment);
                    if (element.Length > 1)
                    {
                        var elementKey = element[0];
                        var elementValue = element[1];
                        var value = WebUtility.UrlDecode(elementValue);
                        result.Add(elementKey, value);
                    }
                    else
                    {
                        result.Add(itemValue, itemValue);
                    }
                }
            }
            return result;
        }

    }
}
