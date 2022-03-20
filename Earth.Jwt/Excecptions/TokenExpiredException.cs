using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Earth.Jwt.Model;

namespace Earth.Jwt.Exceptions
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
