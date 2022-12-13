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
using AspNetCoreIdentity.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNetCoreIdentity.Controllers
{
    public class AccountsController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IUserClaimsPrincipalFactory<ApplicationUser> _claimsPrincipalFactory;
        public AccountsController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IUserClaimsPrincipalFactory<ApplicationUser> claimsPrincipalFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _claimsPrincipalFactory = claimsPrincipalFactory;
        }



        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.UserName,
                    Email = model.Email,
                    EmailConfirmed = true,
                    PhoneNumber = model.UserPhone,
                    PhoneNumberConfirmed = true,
                    TwoFactorEnabled = true
                };

                Microsoft.AspNetCore.Identity.IdentityResult result =
                    await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    TempData["Success"] = "It's created";
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                }
            }
            return View(model);
        }


        [HttpGet]
        public IActionResult Login(string returnUrl)
        {

            ViewBag.returnUrl = returnUrl ?? "/";
            return View();
        }




        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    return RedirectToAction("Index", "Home");
                }
                // before this you have to check the user password also
                // but for demo purpose I will skip this check
                await _signInManager.SignOutAsync();

                AuthenticationProperties properties = new AuthenticationProperties
                {
                    AllowRefresh = true,
                    IsPersistent = false,
                    RedirectUri = returnUrl ?? "/"
                };

                if (await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    var validProviders = await _userManager.GetValidTwoFactorProvidersAsync(user);
                    if (validProviders.Contains("Identity.TwoFactorUserId"))
                    {
                        var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Identity.TwoFactorUserId");
                        Debug.WriteLine(token);

                        await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, Store2FA(user.Id, "Identity.TwoFactorUserId"));
                        return RedirectToAction("TwoFactor");
                    }
                }
                await _signInManager.SignInAsync(user, properties);
                return Redirect(returnUrl ?? "/");
          
            }
            return View(model);
        }

        [HttpGet]
        public IActionResult TwoFactor()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFAuthModel model)
        {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Your login request has expired, please start over");
                return View(model);
            }

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));

                if (user != null)
                {
                    //await _userManager.GetUserIdAsync
                    var isValid = await _userManager.VerifyTwoFactorTokenAsync(user,
                        result.Principal.FindFirstValue("amr"), model.Token);

                    if (isValid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

                        var claimsPrincipal = await _claimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                        return RedirectToAction("Index", "Home");
                    }

                    ModelState.AddModelError("", "Invalid token");
                    return View(model);
                }

                ModelState.AddModelError("", "Invalid Request");
            }

            return View(model);

        }

        private ClaimsPrincipal Store2FA(string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                // authentication method reference which indicate how the user authenticated to our application
                new Claim("amr", provider) 
            }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

    }
}
