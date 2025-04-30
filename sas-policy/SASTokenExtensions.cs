using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace N2.Security.Sas
{
    public static class SASTokenExtensions
    {
        public static IServiceCollection AddSasTokensFromSettings(this IServiceCollection services)
        {
            services.TryAddSingleton<ISasPolicyRepository, SasPolicyFromSettings>();
            services.TryAddSingleton<ISasTokenValidator, SasTokenValidator>();
            return services;
        }

        public static IApplicationBuilder UseSasTokens(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SasTokenMiddleware>();
        }

        /// <summary>
        ///     returns a string representation of this token for use in a URL
        /// </summary>
        public static string ToQueryString(this ISasTokenParameters token)
        {
            var components = new List<string>
            {
                $"sr={WebUtility.UrlEncode(string.Join(',', token.SharedResource))}"
            };

            if (!string.IsNullOrEmpty(token.Signature))
            {
                components.Add($"sig={WebUtility.UrlEncode(token.Signature)}");
            }

            if (token.Expiry > 0)
            {
                components.Add($"se={token.Expiry}");
            }

            if (!string.IsNullOrEmpty(token.Nonce))
            {
                components.Add($"nonce={WebUtility.UrlEncode(token.Nonce)}");
            }

            if (!string.IsNullOrEmpty(token.SigningKeyName))
            {
                components.Add($"skn={WebUtility.UrlEncode(token.SigningKeyName)}");
            }

            if (token.AdditionalValues != null)
            {
                foreach (var kvp in token.AdditionalValues)
                {
                    components.Add($"{kvp.Key.ToLowerInvariant()}={WebUtility.UrlEncode(kvp.Value)}");
                }
            }
            return string.Join("&", components);
        }

        public static string CalcSignature(this ISasTokenParameters token, string sharedSecret, HashType hashType)
        {
            return CalcSignature(token, sharedSecret, false, hashType, null);
        }

        public static bool ValidateSigningKeyPolicies(string sharedSecret)
        {
            return sharedSecret.Length >= 20;
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
        public static string CalcSignature(this ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType, IEnumerable<string>? additionalKeys)
        {
            // to be safe, the sharedsecret should contain at least 20 characters.
            // this also limits the number of erroneous switch of the key name and shared secret
            var keyPolicyCheck = ValidateSigningKeyPolicies(sharedSecret);
            if (!keyPolicyCheck)
            {
                throw new ArgumentOutOfRangeException(nameof(sharedSecret), TokenResponseCode.InvalidSigningKey.Description());
            }

            var stringToSign = WebUtility.UrlEncode(string.Join(',', token.SharedResource)) + "\n";

            if (additionalKeys != null && token.AdditionalValues != null)
            {
                foreach (var key in additionalKeys)
                {
                    var kvp = token.AdditionalValues.FirstOrDefault(q => q.Key == key);
                    if (kvp.Key == null)
                    {
                        throw new ArgumentException($"Value is missing from additional values : {key}", nameof(token));
                    }

                    stringToSign += $"{kvp.Key}={WebUtility.UrlEncode(kvp.Value)}\n";
                }
            }
            if (useNonce)
            {
                if (string.IsNullOrEmpty(token.Nonce))
                {
                    throw new ArgumentException("Nonce is required.", nameof(token));
                }
                stringToSign += $"{WebUtility.UrlEncode(token.Nonce)}\n";
            }

            stringToSign += token.Expiry;
            return CalculateHash(sharedSecret, hashType, stringToSign);
        }

        public static string CalculateHash(string sharedSecret, HashType hashType, string stringToSign)
        {
            string signature;
            switch (hashType)
            {
                default:
                    throw new NotSupportedException($"Hashing using {hashType} is not supported");
                case HashType.MD5:
                    using (var md5 = MD5.Create())
                    {
                        var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(stringToSign + '\n' + sharedSecret));
                        signature = BitConverter.ToString(bytes)
                            .Replace("-", string.Empty)
                            .ToLowerInvariant();
                    }
                    break;
                case HashType.Sha1:
                    using (var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
                case HashType.Sha256:
                    // This should be the default. Before using other methods, verify if the client system supports it.
                    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
                case HashType.Sha384:
                    using (var hmac = new HMACSHA384(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
                case HashType.Sha512:
                    using (var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
#if NET8_0_OR_GREATER
                case HashType.SHA3_256:
                    using (var hmac = new HMACSHA3_256(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
                case HashType.SHA3_384:
                    using (var hmac = new HMACSHA3_384(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
                case HashType.SHA3_512:
                    using (var hmac = new HMACSHA3_512(Encoding.UTF8.GetBytes(sharedSecret)))
                    {
                        signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
                    }
                    break;
#endif
            }

            return signature;
        }

        public static T? GetValue<T>(this IDictionary<string, string> items, string key)
        {
            object result;
            var type = typeof(T);
            var item = default(T);
            if (!items.TryGetValue(key, out var value))
            {
                return default;
            }

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

            if (string.IsNullOrEmpty(queryString))
            {
                return result;
            }

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
