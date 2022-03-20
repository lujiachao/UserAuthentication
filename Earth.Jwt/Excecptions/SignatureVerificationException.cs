using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Exceptions
{
    /// <summary>
    /// 签名验签异常
    /// </summary>
    public class SignatureVerificationException : Exception
    {
        private const string ExpectedKey = "Expected";
        private const string ReceivedKey = "Received";


        public SignatureVerificationException(string message)
            : base(message)
        {
        }
    }
}
