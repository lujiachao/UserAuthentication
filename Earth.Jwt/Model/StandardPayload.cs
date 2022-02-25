using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Model
{
    public class StandardPayload
    {
        /// <summary>
        /// 发行人
        /// </summary>
        public string iss { get; set; }
        /// <summary>
        /// 主题
        /// </summary>
        public string sub { get; set; }
        /// <summary>
        /// 接收方
        /// </summary>
        public string aud { get; set; }
        /// <summary>
        /// 过期时间
        /// </summary>
        public string exp { get; set; }
        /// <summary>
        /// 生效时间
        /// </summary>
        public string nbf { get; set; }
        /// <summary>
        /// 签发时间
        /// </summary>
        public string iat { get; set; }
        /// <summary>
        /// 唯一身份标识
        /// </summary>
        public string jti { get; set; }
    }
}
