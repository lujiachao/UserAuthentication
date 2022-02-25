using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Excecptions
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

        public SignatureVerificationException(string decodedCrypto, params string[] decodedSignatures)
            : this("Invalid signature")
        {
            Expected = decodedCrypto;
            Received = $"{String.Join(",", decodedSignatures)}";
        }


        public string Expected
        {
            get => GetOrDefault<string>(ExpectedKey);
            internal set => Data.Add(ExpectedKey, value);
        }

        public string Received
        {
            get => GetOrDefault<string>(ReceivedKey);
            internal set => Data.Add(ReceivedKey, value);
        }


        protected T GetOrDefault<T>(string key) =>
            Data.Contains(key) ? (T)Data[key] : default(T);
    }
}
