using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Excecptions
{
    /// <summary>
    /// 非法Token
    /// </summary>
    public class IllegalTokenException : Exception
    {
        public IllegalTokenException(string msg) : base(msg) { }

        public IllegalTokenException(string msg, Exception ex) : base(msg, ex) { }
    }
}
