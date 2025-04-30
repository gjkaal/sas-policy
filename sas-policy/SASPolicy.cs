using System.Collections.Generic;

namespace N2.Security.Sas
{
    /// <summary>
    /// Class SASPolicy.
    /// </summary>
    /// <remarks>
    /// no comments
    /// </remarks>
    public class SASPolicy : ISasPolicy
    {
        /// <summary>
        /// Gets the default token time-out.
        /// </summary>
        public const int DefaultTokenTimeOut = 300;

        /// <summary>
        /// The permissions that are allowed for this policy.
        /// </summary>
        public string[] AllowedPermissions { get; set; } = [];

        /// <summary>
        /// Gets or sets the resource identifier.
        /// </summary>
        /// <value>
        /// The identifier.
        /// </value>
        /// <remarks>
        /// no comments
        /// </remarks>
        public string SharedResourceExpression { get; set; } = ".*";

        /// <summary>
        /// Gets or sets the name of the policy.
        /// </summary>
        /// <value>
        /// The name of the policy.
        /// </value>
        /// <remarks>
        /// no comments
        /// </remarks>
        public string Skn { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the shared key used to generate a SAS token.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        /// <remarks>
        /// no comments
        /// </remarks>
        public string Key { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the type name of the protect object.
        /// </summary>
        /// <value>
        /// The name of the type.
        /// </value>
        /// <remarks>
        /// no comments
        /// </remarks>
        public string TypeName { get; set; } = nameof(SASPolicy);

        /// <summary>
        /// Gets or sets a value indicating whether to use a nonce when validating.
        /// </summary>
        /// <value>
        /// <c>true</c> if [use nonce]; otherwise, <c>false</c>.
        /// </value>
        public bool UseNonce { get; set; }

        /// <summary>
        /// Gets or sets the type of the hash.
        /// </summary>
        /// <value>
        /// The type of the hash.
        /// </value>
        public HashType HashType { get; set; } = HashType.None;

        /// <summary>
        /// Gets or sets the token time out in seconds.
        /// </summary>
        /// <value>
        /// A positive integer value.
        /// </value>
        public int TokenTimeOut { get; set; } = DefaultTokenTimeOut;

        /// If any additional keys are required, add them to this list
        public ICollection<string> AdditionalKeys { get; set; } = [];

        /// <summary>
        /// Indicates if the policy has claims.
        /// </summary>
        public bool HasClaims { get; set; }
    }
}