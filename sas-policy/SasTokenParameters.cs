using System.Collections.Generic;

namespace Nice2Experience.SasPolicy
{
    /// <summary>
    ///     represents a SAS-token. (Shared Access Signature)
    /// </summary>
    public class SasTokenParameters : ISasTokenParameters
    {
        /// <summary>
        ///     skn
        /// </summary>
        public string SigningKey { get; set; }

        /// <summary>
        ///     sr
        /// </summary>
        public string SharedResource { get; set; }

        /// <summary>
        ///     sig
        /// </summary>
        public string Signature { get; set; }

        /// <summary>
        ///     se
        /// </summary>
        public int Expiry { get; set; }


        public string Nonce { get; set; }

        /// <summary>
        ///     Other values in request, used for signature
        /// </summary>
        public IDictionary<string, string> AdditionalValues { get; set; }

        /// <summary>
        /// If parsed from a query string, this value is set is key elements are missing
        /// </summary>
        public bool Invalid { get; set; }
    }
}