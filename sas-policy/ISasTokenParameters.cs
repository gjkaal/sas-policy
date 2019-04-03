using System.Collections.Generic;

namespace Nice2Experience.SasPolicy
{
    public interface ISasTokenParameters
    {
        int Expiry { get; set; }
        string Nonce { get; set; }
        string SharedResource { get; set; }
        string Signature { get; set; }
        string SigningKey { get; set; }
        IDictionary<string, string> AdditionalValues { get; set; }
    }
}
