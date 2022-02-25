using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Earth.Jwt.Model
{
    public abstract class JWTBase : JWTBase<string, string>
    {
        public JWTBase() : base(StringComparer.OrdinalIgnoreCase)
        {

        }

        public new string ToString()
        {
            var count = Count();

            if (count > 0)
            {
                int i = 0;
                StringBuilder sb = new StringBuilder();
                sb.Append("{");
                foreach (var item in this)
                {
                    i++;
                    if (i == 1)
                        sb.Append($"\"{item.Key}\":\"{item.Value}\"");
                    else
                        sb.Append($",\"{item.Key}\":\"{item.Value}\"");
                }
                sb.Append("}");
                return sb.ToString();
            }
            return base.ToString();
        }
    }

    public abstract class JWTBase<TK, TV> : IEnumerable<KeyValuePair<TK, TV>>
    {
        Dictionary<TK, TV> _dic;

        public TV this[TK key]
        {
            get
            {
                if (_dic.ContainsKey(key))
                    return _dic[key];
                else
                    return default(TV);
            }
            set
            {
                _dic[key] = value;
            }
        }


        public JWTBase(IEqualityComparer<TK> comparer)
        {
            _dic = new Dictionary<TK, TV>(comparer);
        }

        public IEnumerator<KeyValuePair<TK, TV>> GetEnumerator()
        {
            return _dic.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public bool IsEmput
        {
            get
            {
                return _dic.Count == 0;
            }
        }

        public void TryAdd(TK key, TV val)
        {
            if (!_dic.ContainsKey(key))
            {
                _dic.Add(key, val);
            }
        }

        public bool HavingKey(TK key)
        {
            if (_dic.ContainsKey(key))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public void TryRemove(TK key)
        {
            if (_dic.ContainsKey(key))
            {
                _dic.Remove(key);
            }
        }

        public int Count()
        {
            return _dic.Count;
        }
    }
}
