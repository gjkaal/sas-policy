using System.Collections.Generic;

namespace Nice2Experience.Security.Sas
{
    /// <summary>
    /// Class SASPolicy.
    /// </summary>
    /// <remarks>no comments</remarks>
    public class SASPolicy : ISasPolicy
    {
        /// <summary>
        ///     Gets the default length of the key.
        /// </summary>
        /// <value>The default length of the key.</value>
        /// <remarks>no comments</remarks>
        public const int DefaultKeyLength = 64;

        /// <summary>
        ///     Gets or sets the permissions allowed for this policy.
        /// </summary>
        /// <value>The permissions.</value>
        public Permissions Permissions { get; set; }

        /// <summary>
        ///     Gets or sets the resource identifier.
        /// </summary>
        /// <value>The identifier.</value>
        /// <remarks>no comments</remarks>
        public string SharedResourceExpression { get; set; }

        /// <summary>
        ///     Gets or sets the name of the policy.
        /// </summary>
        /// <value>The name of the policy.</value>
        /// <remarks>no comments</remarks>
        public string Skn { get; set; }

        /// <summary>
        ///     Gets or sets the shared key used to generate a SAS token.
        /// </summary>
        /// <value>The key.</value>
        /// <remarks>no comments</remarks>
        public string Key { get; set; }

        /// <summary>
        ///     Gets or sets the type name of the protect object.
        /// </summary>
        /// <value>The name of the type.</value>
        /// <remarks>no comments</remarks>
        public string TypeName { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to use a nonce when validating.
        /// </summary>
        /// <value><c>true</c> if [use nonce]; otherwise, <c>false</c>.</value>
        public bool UseNonce { get; set; }

        /// <summary>
        ///     Gets or sets the type of the hash.
        /// </summary>
        /// <value>The type of the hash.</value>
        public HashType HashType { get; set; }

        /// <summary>
        ///     Gets or sets the token time out.
        /// </summary>
        /// <value>The token time out.</value>
        public int TokenTimeOut { get; set; }

        /// If any additional keys are required, add them to this list
        public ICollection<string> AdditionalKeys { get; set; }

    }
}