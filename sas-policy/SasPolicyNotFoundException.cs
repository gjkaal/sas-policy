using System;
using System.Collections.Generic;

namespace N2.Security.Sas
{
    public class SasPolicyNotFoundException : KeyNotFoundException
    {
        public string KeyName { get; set; } = string.Empty;

        public SasPolicyNotFoundException(string message) : base(message)
        {
        }
        public SasPolicyNotFoundException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public SasPolicyNotFoundException(string message, string keyName) : base(message)
        {
            KeyName = keyName;
        }
    }
}