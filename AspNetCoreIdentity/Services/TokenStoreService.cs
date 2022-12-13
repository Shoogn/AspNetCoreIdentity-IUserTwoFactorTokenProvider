/*
**  Copyright 2022 Mohammed Ahmed Hussien babiker
**  Licensed under the Apache License, Version 2.0 (the "License");
**  you may not use this file except in compliance with the License.
**  You may obtain a copy of the License at
**  http://www.apache.org/licenses/LICENSE-2.0
**  Unless required by applicable law or agreed to in writing, software
**  distributed under the License is distributed on an "AS IS" BASIS,
**  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**  See the License for the specific language governing permissions and
** limitations under the License.
 */

using System.Collections.Concurrent;

namespace AspNetCoreIdentity.Services
{
    public class TokenStoreService : ITokenStoreService
    {
        private readonly ConcurrentDictionary<string, string> _tokenProviderStore = new ConcurrentDictionary<string, string>();

        public bool RemoveToken(string key)
        {
            var result = _tokenProviderStore.TryRemove(key, out _);
            return result; 
        }

        public bool StoreToken(string key, string token)
        {
            if (!_tokenProviderStore.ContainsKey(key))
            {
                var result = _tokenProviderStore.TryAdd(key, token);
                return result;
            }
            return false;
        }

        public string GetToken(string key)
        {
            var result = _tokenProviderStore.TryGetValue(key, out string token );
            if(result)
                return token;
            return null;
        }
    }
}
