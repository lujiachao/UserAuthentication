using Earth.Jwt.Common;
using Earth.Jwt.Encryption;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Earth.Jwt.Model
{
    /// <summary>
    /// JWTPayload
    /// </summary>
    public class JWTPayload<T> : JWTBase where T : class
    {
        public T Data { get; set; }

        /// <summary>
        /// JWTPayload
        /// </summary>
        public JWTPayload()
        {

        }

        /// <summary>
        /// JWTPayload
        /// </summary>
        public JWTPayload(T t, int timeoutSencond)
        {
            this.Data = t;
            this["exp"] = JwtDateTime.Now.AddSeconds(timeoutSencond).GetTimeStampStr();
            if (t != null)
                if (t.GetType() != typeof(string))
                    this["data"] = JsonSerializer.Serialize(t).Replace("\"", "\\\"");
                else
                    this["jti"] = t.ToString();

        }

        /// <summary>
        /// JWTPayload
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="base64Str"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public virtual JWTPayload<T> Parse(string base64Str, Encoding encoding)
        {
            var json = encoding.GetString(Base64URL.Decode(base64Str));
            JsonDocument jd = JsonDocument.Parse(json);
            var payload = new JWTPayload<T>();
            foreach (var jsonProperty in jd.RootElement.EnumerateObject())
            {
                payload[jsonProperty.Name] = jsonProperty.Value.ToString();
            }
            if (payload.HavingKey("data"))
            {
                payload.Data = JsonSerializer.Deserialize<T>(payload["data"]);
                payload["data"] = payload["data"].Replace("\"", "\\\"");
                return payload;
            }
            else
            {
                payload.Data = payload["jti"] as T;
                return payload;
            }

        }

        public virtual string ToBase64Str(Encoding encoding)
        {
            return Base64URL.Encode(encoding.GetBytes(this.ToString()));
        }

        public virtual bool IsExpired()
        {
            return JwtDateTime.IsExpired(this["exp"]);
        }
    }
}
