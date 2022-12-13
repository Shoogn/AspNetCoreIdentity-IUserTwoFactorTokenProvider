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

using AspNetCoreIdentity.Models;
using AspNetCoreIdentity.Services;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading.Tasks;

namespace AspNetCoreIdentity.Helpers
{
    public class CustomTwoFactorTokenProvider : IUserTwoFactorTokenProvider<ApplicationUser>
    {
        private readonly ITokenStoreService _tokenStoreService;
        public CustomTwoFactorTokenProvider(ITokenStoreService tokenStoreService)
        {
            _tokenStoreService = tokenStoreService;
        }
        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
        {
            return Task.FromResult(manager.SupportsUserTwoFactor);
        }

        public Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser> manager, ApplicationUser user)
        {
            Random random = new Random();
            int token = random.Next(1000, 9999);

            if (_tokenStoreService.StoreToken(user.Id, token.ToString()))
                return Task.FromResult(token.ToString());

            return Task.FromResult(string.Empty);
        }

        public Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser> manager, ApplicationUser user)
        {
            var storedToken = _tokenStoreService.GetToken(user.Id);
            if (storedToken != null)
            {
                bool result = storedToken.Equals(token);
                _tokenStoreService.RemoveToken(user.Id);

                return Task.FromResult(result);
            }
            return Task.FromResult(false);
        }
    }
}
