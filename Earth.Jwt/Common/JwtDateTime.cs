using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Earth.Jwt.Common
{
    public static class JwtDateTime
    {
        public static DateTime Now
        {
            get
            {
                return DateTime.Now;
            }
        }

        public static long GetTimeStamp(this DateTime dt)
        {
            return (dt.Ticks - TimeZoneInfo.ConvertTime(new System.DateTime(1970, 1, 1, 8, 0, 0, 0), TimeZoneInfo.Local).Ticks) / 1000;
        }

        public static string GetTimeStampStr(this DateTime dt)
        {
            return dt.GetTimeStamp().ToString();
        }

        /// <summary>
        /// 是否已过期
        /// </summary>
        /// <param name="unixTickStr"></param>
        /// <returns></returns>
        public static bool IsExpired(string unixTickStr)
        {
            if (string.IsNullOrEmpty(unixTickStr)) return true;

            if (long.TryParse(unixTickStr, out long unixTick))
            {
                if (unixTick >= Now.GetTimeStamp())
                {
                    return false;
                }
            }
            return true;
        }
    }
}
