using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Earth.Jwt.Encryption;

namespace Earth.Jwt.Model
{
    public class JWTHeader : JWTBase
    {
        public JWTHeader(string alg = "HS256", string typ = "JWT")
        {
            if (!string.IsNullOrWhiteSpace(alg))
            {
                TryAdd("alg", alg);
            }

            if (!string.IsNullOrWhiteSpace(typ))
            {
                TryAdd("typ", typ);
            }  
        }

        public virtual JWTHeader Parse(string base64Str, Encoding encoding)
        {
            var json = encoding.GetString(Base64URL.Decode(base64Str));
            JsonDocument jd = JsonDocument.Parse(json);
            var header = new JWTHeader(string.Empty, string.Empty);
            foreach (var jsonProperty in jd.RootElement.EnumerateObject())
            {
                header[jsonProperty.Name] = jsonProperty.Value.ToString();
            }
            return header;
        }

        public virtual string ToBase64Str(Encoding encoding)
        {
            return Base64URL.Encode(encoding.GetBytes(this.ToString()));
        }
    }
}
