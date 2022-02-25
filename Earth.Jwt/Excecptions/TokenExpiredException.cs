using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Excecptions
{
    /// <summary>
    /// Token过期异常
    /// </summary>
    public class TokenExpiredException : SignatureVerificationException
    {
        private const string PayloadDataKey = "PayloadData";
        private const string ExpirationKey = "Expiration";


        public TokenExpiredException(string message)
             : base(message)
        {
        }
    }
}
