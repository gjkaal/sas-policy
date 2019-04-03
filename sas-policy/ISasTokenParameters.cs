using System.Collections.Generic;

namespace Nice2Experience.Security.Sas
{
    public interface ISasTokenParameters
    {
        int Expiry { get; set; }
        string Nonce { get; set; }
        string SharedResource { get; set; }
        string Signature { get; set; }
        string SigningKeyName { get; set; }
        IDictionary<string, string> AdditionalValues { get; set; }
    }
}
