using System.Collections.Generic;

namespace Nice2Experience.SasPolicy
{
    public interface ISasTokenValidator
    {
        ISasTokenValidationResult Validate(ISasTokenParameters token);
        ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType);
        ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, bool useNonce, HashType hashType, IEnumerable<string> additionalKeys);
        ISasTokenValidationResult Validate(ISasTokenParameters token, string sharedSecret, HashType hashType);
        ISasTokenValidationResult Validate(string queryString);
        ISasTokenValidationResult Validate(string queryString, IEnumerable<string> additionalKeys);
        ISasTokenValidationResult Validate(string queryString, bool ignoreTimeout);
        ISasTokenValidationResult Validate(string queryString, string sharedSecret);
        ISasTokenValidationResult Validate(string queryString, string sharedSecret, HashType hashType);
        ISasTokenValidationResult Validate(string queryString, string sharedSecret, IEnumerable<string> additionalKeys);
        ISasTokenValidationResult Validate(string queryString, string sharedSecret, HashType hashType, IEnumerable<string> additionalKeys);
        void ValidateAndThrowException(string queryString, string sharedSecret, HashType hashType);
    }
}