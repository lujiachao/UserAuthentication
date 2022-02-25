using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Encryption
{
    /// <summary>
    /// HMACSHA256加密
    /// </summary>
    public static class HMACSHA256
    {
        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="password"></param>
        /// <param name="bytesToSign"></param>
        /// <returns></returns>
        public static byte[] Sign(byte[] password, byte[] bytesToSign)
        {
            using (var sha = new System.Security.Cryptography.HMACSHA256(password))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }
    }
}
