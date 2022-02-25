using Earth.Jwt.Encryption;
using Earth.Jwt.Excecptions;
using Earth.Jwt.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt
{
    /// <summary>
    /// JWTPackage
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class JWTPackage<T> where T : class
    {
        public const string Prex = "Bearer ";

        protected Encoding _encoding;

        /// <summary>
        /// 密码
        /// </summary>
        protected string _password;

        /// <summary>
        /// 头部
        /// </summary>
        public virtual JWTHeader Header { get; set; }
        /// <summary>
        /// 负载
        /// </summary>
        public virtual JWTPayload<T> Payload { get; set; }
        /// <summary>
        /// 签名
        /// </summary>
        public virtual string Signature
        {
            get
            {
                var headerStr = Header.ToBase64Str(_encoding);

                var payloadStr = Payload.ToBase64Str(_encoding);

                var packageStr = $"{headerStr}.{payloadStr}";

                return $"{packageStr}.{Base64URL.Encode(HMACSHA256.Sign(_encoding.GetBytes(_password), _encoding.GetBytes(packageStr)))}";
            }
        }

        /// <summary>
        /// JWT包
        /// </summary>
        /// <param name="t">数据</param>
        /// <param name="timeOutSenconds">过期时间</param>
        /// <param name="password">密码</param>
        public JWTPackage(T t, int timeOutSenconds, string password) : this(new JWTPayload<T>(t, timeOutSenconds), password, Encoding.UTF8) { }


        /// <summary>
        /// JWT包
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="password"></param>
        /// <param name="encoding"></param>
        public JWTPackage(JWTPayload<T> payload, string password, Encoding encoding)
        {
            _encoding = encoding;

            _password = password;

            Payload = payload;

            Header = new JWTHeader();
        }

        public JWTPackage(JWTHeader header, JWTPayload<T> payload, string password, Encoding encoding)
        {
            _encoding = encoding;

            _password = password;

            Header = header;

            Payload = payload;
        }

        /// <summary>
        /// 获取http header键值对
        /// </summary>
        /// <returns></returns>
        public virtual KeyValuePair<string, string> GetAuthorizationBearer()
        {
            return new KeyValuePair<string, string>("Authorization", $"{Prex}{Signature}");
        }

        /// <summary>
        /// 解析为JWTPackage
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="password"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public virtual JWTPackage<T> Parse(string signature, string password, Encoding encoding)
        {
            if (string.IsNullOrEmpty(signature)) throw new IllegalTokenException("Parameter cannot be empty");

            var arr = signature.Split(new string[] { "." }, StringSplitOptions.RemoveEmptyEntries);

            if (arr == null || arr.Length != 3) throw new IllegalTokenException("JWT Package failed to parse signature, signature format is incorrect");

            JWTPackage<T> jwtPackage;

            try
            {
                jwtPackage = new JWTPackage<T>(Header.Parse(arr[0], encoding), Payload.Parse(arr[1], encoding), password, encoding);
            }
            catch (Exception ex)
            {
                throw new IllegalTokenException("JWT Package failed to parse signature, signature format is incorrect", ex);
            }

            if (jwtPackage == null) throw new IllegalTokenException("JWT Package failed to parse signature, signature format is incorrect");

            if (jwtPackage.Signature != signature) throw new SignatureVerificationException("JWT Package failed to parse signature");

            if (jwtPackage.Payload.IsExpired()) throw new TokenExpiredException("The token of jwtpackage has expired");

            return jwtPackage;
        }

        /// <summary>
        /// 解析为JWTPackage
        /// </summary>
        /// <param name="signature"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public virtual JWTPackage<T> Parse(string signature, string password)
        {
            return Parse(signature, password, Encoding.UTF8);
        }
    }
}
