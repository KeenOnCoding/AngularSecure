
using Microsoft.AspNetCore.Mvc;

using System.Threading.Tasks;
using IdentityServer4.Services;
using System.Linq;
using System;
using IdentityServer4.Stores;
using IdentityServer4.Models;
using IdentityServer4.Events;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace AngularSecure.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IClientStore _clientStore;
        private readonly IEventService _events;


        public AccountController(SignInManager<ApplicationUser> signInManager, 
            UserManager<ApplicationUser> userManager, 
            IIdentityServerInteractionService interaction, 
            IAuthenticationSchemeProvider schemeProvider, 
            IClientStore clientStore, IEventService events)
        {
            _userManager = userManager;
            _interaction = interaction;
            _schemeProvider = schemeProvider;
            _clientStore = clientStore;
            _events = events;
            _signInManager = signInManager;
        }


        [HttpGet]
        public async Task<IActionResult> OnGetAsync(string returnUrl)
        {
            

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync("none@gmail.com", "Ryabushenko777*", true, lockoutOnFailure: false);
                if (result.Succeeded)
                {

                    return LocalRedirect("~/");
                }

            }
            return LocalRedirect("~/");
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {

            return await Task.FromResult(LocalRedirect(returnUrl));
        }
    }
}
