using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Encryption
{
    /// <summary>
    /// Base64URL
    /// 基于JWT规范的Base64编码/解码实现
    /// </summary>
    public static class Base64URL
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Encode(byte[] input)
        {
            if (input is null)
                throw new ArgumentNullException(nameof(input));
            if (input.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(input));

            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0];
            output = output.Replace('+', '-');
            output = output.Replace('/', '_');
            return output;
        }
        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] Decode(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException(nameof(input));

            var output = input;
            output = output.Replace('-', '+');
            output = output.Replace('_', '/');
            switch (output.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    output += "==";
                    break;
                case 3:
                    output += "=";
                    break;
                default:
                    throw new FormatException("非法 base64url 字符串。");
            }
            return Convert.FromBase64String(output);
        }
    }
}
