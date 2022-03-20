using Earth.Jwt.Common;
using Earth.Jwt.Encryption;
using Earth.Jwt.Exceptions;
using Earth.Jwt.Model;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

namespace Earth.Jwt.UnitTest
{
    [TestClass]
    public class JwtTest
    {
        private string _password = "MTIzNDU2Nzg5YWJj";
        private string _passwordTwo = "MTIzNDU2Nzg5YWJo";
        private string _toSignStr = "10001";
        private TestMode _testMode = new TestMode()
        {
            Test1 = "123",
            Test2 = "456"
        };
        private StandardPayload _testStandardPayload = new StandardPayload()
        {
            iss = "发行人",
            sub = "主题",
            aud = "接收方",
            exp = "过期时间",
            nbf = "生效时间",
            iat = "签发时间",
            jti = "唯一身份标识"
        };

        /// <summary>
        /// signature为空判断
        /// </summary>
        [TestMethod]
        public void SignatureNullTest()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.GetAuthorizationPrex();
            try
            {
                var jwpt2 = jWTPackage.Parse(null, _password);
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("Parameter cannot be empty", iex.Message);
            }
        }

        /// <summary>
        /// parse signature失败
        /// </summary>
        [TestMethod]
        public void FaildParseSignature()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.GetAuthorizationPrex();
            try
            {
                var jwpt2 = jWTPackage.Parse(".", _password);
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("JWT Package failed to parse signature, signature format is incorrect", iex.Message);
            }
        }

        /// <summary>
        /// 时间过期判断
        /// </summary>
        [TestMethod]
        public void UnixTickExpired()
        {
            var isExpired = JwtDateTime.IsExpired("");
            Assert.IsTrue(isExpired);
        }

        /// <summary>
        /// 获取http header键值对
        /// </summary>
        [TestMethod]
        public void TestAuthorizationBearer()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.GetAuthorizationPrex();
            var jwpt2 = jWTPackage.Parse(jWTPackage.ResolveAuthorizationPrex(sign.Value), _password);
            var jwpt3 = jWTPackage.Parse(jWTPackage.ResolveAuthorizationPrex(sign), _password);
            Assert.AreEqual(jwpt2.Payload["jti"], _toSignStr);
            Assert.AreEqual(jwpt3.Payload["jti"], _toSignStr);
            try
            {
                jWTPackage.ResolveAuthorizationPrex(sign.Value, "abc");
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("PrexSignature is not equip prex", iex.Message);
            }

            try
            {
                jWTPackage.ResolveAuthorizationPrex(sign, "sdc");
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("PrexSignature is not equip prex", iex.Message);
            }

            try
            {
                jWTPackage.ResolveAuthorizationPrex(sign, "Bearer", "abc");
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("HeaderKey is not equip key", iex.Message);
            }
        }

        /// <summary>
        /// 测试string类型用户信息
        /// </summary>
        [TestMethod]
        public void TestString()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign, _password);
                Assert.Equals(jwpt2.Payload["jti"], _toSignStr);
            }
            catch (IllegalTokenException iex)
            {
                System.Console.WriteLine($"Parsing failed：{iex.Message}");
            }
            catch (TokenExpiredException tex)
            {
                System.Console.WriteLine($"Parsing failed：{tex.Message}");
            }
            catch (SignatureVerificationException sex)
            {
                System.Console.WriteLine($"Parsing failed：{sex.Message}");
            }
            catch (Exception ex)
            {
                System.Console.WriteLine($"Parsing failed：{ex.Message}");
            }
        }

        /// <summary>
        /// 测试string类型用户信息 测试token过期
        /// </summary>
        [TestMethod]
        public void TestStringExpired()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, -60, _password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign, _password);
            }
            catch (TokenExpiredException tex)
            {
                Assert.AreEqual("The token of jwtpackage has expired", tex.Message);
            }
        }

        /// <summary>
        /// 测试string类型用户信息 测试token格式错误
        /// </summary>
        [TestMethod]
        public void TestStringTokenError()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign.Split(".")[0], _password);
            }
            catch (IllegalTokenException iex)
            {
                Assert.AreEqual("JWT Package failed to parse signature, signature format is incorrect", iex.Message);
            }
        }


        /// <summary>
        /// 测试string类型用户信息 测试jwt验证错误
        /// </summary>
        [TestMethod]
        public void TestStringVerification()
        {
            var jWTPackage = new JWTPackage<string>(_toSignStr, 60, _password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign, _passwordTwo);
            }
            catch (SignatureVerificationException sex)
            {
                Assert.AreEqual("JWT Package failed to parse signature", sex.Message);
            }
        }

        /// <summary>
        /// 测试泛型类型用户信息
        /// </summary>
        [TestMethod]
        public void TestT()
        {
            var jWTPackage = new JWTPackage<TestMode>(_testMode, 3600, _password);
            var sign = jWTPackage.Signature;
            var jwpt2 = jWTPackage.Parse(sign, _password);
            Assert.AreEqual(JsonSerializer.Serialize(jwpt2.Payload.Data), JsonSerializer.Serialize(_testMode));
        }

        /// <summary>
        /// 测试泛型类型用户信息
        /// </summary>
        [TestMethod]
        public void TestStandardPayload()
        {
            var jWTPackage = new JWTPackage<StandardPayload>(_testStandardPayload, 3600, _password);
            var sign = jWTPackage.Signature;
            var jwpt2 = jWTPackage.Parse(sign, _password);
            Assert.AreEqual(JsonSerializer.Serialize(jwpt2.Payload.Data, new JsonSerializerOptions()
            {
                Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
            }), JsonSerializer.Serialize(_testStandardPayload, new JsonSerializerOptions()
            {
                Encoder = JavaScriptEncoder.Create(UnicodeRanges.All)
            }));
        }

        /// <summary>
        /// 加密分支单元测试
        /// </summary>
        [TestMethod]
        public void TestEncode()
        {
            try
            {
                Base64URL.Encode(null);
            }
            catch (ArgumentNullException ex)
            {
                Assert.AreEqual("Value cannot be null. (Parameter 'input')", ex.Message);
            }

            try
            {
                Base64URL.Encode(new byte[] { });
            }
            catch (ArgumentOutOfRangeException ex)
            {
                Assert.AreEqual("Specified argument was out of the range of valid values. (Parameter 'input')", ex.Message);
            }
        }

        /// <summary>
        ///  解密分支单元测试
        /// </summary>
        [TestMethod]
        public void TestDecode()
        {
            try
            {
                Base64URL.Decode(null);
            }
            catch (ArgumentException ex)
            {
                Assert.AreEqual("input", ex.Message);
            }
            Encoding encoding = Encoding.UTF8;
            var outPut = Base64URL.Decode("c2RzYWRhc2Rhc2Q");
            Assert.AreEqual("sdsadasdasd", encoding.GetString(outPut));

            var outPut2 = Base64URL.Decode("c2RzYWRhc2Rhc2Rzc3NzZA");
            Assert.AreEqual("sdsadasdasdssssd", encoding.GetString(outPut2));
            try
            {
                var outPut3 = Base64URL.Decode("c2RzYWRhc2Rhc2Rzc3NzZA==1");
            }
            catch (FormatException fex)
            {
                Assert.AreEqual("非法 base64url 字符串。", fex.Message);
            }
        }

        /// <summary>
        ///  异常类测试
        /// </summary>
        [TestMethod]
        public void TestThrowException()
        {
            try
            {
                throw new IllegalTokenException("测试异常报错", new Exception("test"));
            }
            catch (Exception ex)
            {
                Assert.AreEqual("测试异常报错", ex.Message);
                Assert.AreEqual("test", ex.InnerException.Message);
            }
        }

        /// <summary>
        ///  header 内容为0个测试
        /// </summary>
        [TestMethod]
        public void TestJwtHeaderZero()
        {
            var jwtHeader = new JWTHeader("", "");
            var isEmpty = jwtHeader.IsEmpty;
            Assert.IsTrue(isEmpty);
            jwtHeader.ToString();
            jwtHeader.TryAdd("alg", "HS256");
            jwtHeader.TryAdd("typ", "JWT");
            foreach (var item in jwtHeader)
            {

            }
            isEmpty = jwtHeader.IsEmpty;
            Assert.IsFalse(isEmpty);
            jwtHeader.TryRemove("alg");
            Assert.AreEqual(jwtHeader.Count(), 1);
        }

        public class TestMode
        {
            public string Test1 { get; set; }

            public string Test2 { get; set; }
        }
    }
}
