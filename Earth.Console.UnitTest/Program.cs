using Earth.Jwt;
using Earth.Jwt.Exceptions;
using System;

namespace Earth.Console.UnitTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            System.Console.WriteLine("Please enter any word to start the test");
            System.Console.ReadLine();
            string password = "MTIzNDU2Nzg5YWJj";
            TestTwo(new TestMode()
            {
                Test1 = "123",
                Test2 = "456"
            }, timeOutInSeconds: 60, password: password);
            TestThree(t: "10001", timeOutInSeconds: 60, password: password);
            System.Console.WriteLine("Enter any key to end the test");
            System.Console.ReadLine();
        }

        /// <summary>
        /// 测试string类型
        /// </summary>
        static void TestThree(string t, int timeOutInSeconds, string password)
        {
            var jWTPackage = new JWTPackage<string>(t, timeOutInSeconds, password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign, password);
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
        /// 测试泛型类型
        /// </summary>
        static void TestTwo<T>(T t, int timeOutInSeconds, string password) where T : class
        {
            var jWTPackage = new JWTPackage<T>(t, timeOutInSeconds, password);
            var sign = jWTPackage.Signature;
            System.Console.WriteLine($"jwt.signature:\r\n{sign}");
            try
            {
                var jwpt2 = jWTPackage.Parse(sign, password);
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

        public class TestMode
        {
            public string Test1 { get; set; }

            public string Test2 { get; set; }
        }
    }
}
