using System.Collections.Generic;

namespace Nice2Experience.Security.Sas
{
    public interface ISasTokenValidator
    {
        ISasTokenValidationResult Validate(ISasTokenParameters token);
        ISasTokenValidationResult Validate(ISasTokenParameters token, bool ignoreTimeout);
        ISasTokenValidationResult Validate(string queryString);
        ISasTokenValidationResult Validate(string queryString, bool ignoreTimeout);
        void ValidateAndThrowException(string queryString);
    }
}