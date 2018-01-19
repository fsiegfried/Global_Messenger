using GlobalMessenger.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;
using System.Net.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Threading.Tasks;
using GlobalMessenger.Models;
using System.Security.Claims;
using GlobalMessenger.Model;
using System.Configuration;
using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
using GlobalMessengerAPI.Models;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using GlobalMessengerAPI.Providers;
using System.Security.Cryptography;
using GlobalMessengerAPI.Results;
using Microsoft.Owin.Security.Cookies;

namespace GlobalMessengerAPI.Controllers
{
    [RoutePrefix("api/account")]
    public class AccountController : BaseApiController
    {

        private readonly IAppConfiguration _configuration;
        private readonly IEncryption _encryption;
        private readonly IFormsAuth _formsAuth;
        private readonly IHttpCache _httpCache;
        private readonly IRecaptcha _recaptcha;
        private readonly IServices _services;
        private readonly ISeContext _context;
        private readonly IUserManager _userManager;
        private ApplicationUserManager _userManager2;

        public AccountController(IAppSensor appSensor, IAppConfiguration configuration, IEncryption encryption, IFormsAuth formsAuth, ISeContext context, IHttpCache httpCache, IUserManager userManager, IRecaptcha recaptcha, IServices services, IUserIdentity userIdentity)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _encryption = encryption ?? throw new ArgumentNullException(nameof(encryption));
            _formsAuth = formsAuth ?? throw new ArgumentNullException(nameof(formsAuth));
            _httpCache = httpCache ?? throw new ArgumentNullException(nameof(httpCache));
            _recaptcha = recaptcha ?? throw new ArgumentNullException(nameof(recaptcha));
            _services = services ?? throw new ArgumentNullException(nameof(services));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }

        /// <summary>
        /// External Login
        /// </summary>
        [AllowAnonymous]
        [Route("ExternalLogins")]
        public IEnumerable<ExternalLoginViewModel> GetExternalLogins(string returnUrl, bool generateState = false)
        {
            IEnumerable<AuthenticationDescription> descriptions = Authentication.GetExternalAuthenticationTypes();
            List<ExternalLoginViewModel> logins = new List<ExternalLoginViewModel>();

            string state;

            if (generateState)
            {
                const int strengthInBits = 256;
                state = RandomOAuthStateGenerator.Generate(strengthInBits);
            }
            else
            {
                state = null;
            }

            foreach (AuthenticationDescription description in descriptions)
            {
                ExternalLoginViewModel login = new ExternalLoginViewModel
                {
                    Name = description.Caption,
                    Url = Url.Route("ExternalLogin", new
                    {
                        provider = description.AuthenticationType,
                        response_type = "token",
                        //client_id = Startup.PublicClientId,
                        redirect_uri = new Uri(Request.RequestUri, returnUrl).AbsoluteUri,
                        state = state
                    }),
                    State = state
                };
                logins.Add(login);
            }

            return logins;
        }

        /// <summary>
        /// External Login
        /// </summary>
        [OverrideAuthentication]
        [HostAuthentication(DefaultAuthenticationTypes.ExternalCookie)]
        [AllowAnonymous]
        [Route("ExternalLogin", Name = "ExternalLogin")]
        public async Task<IHttpActionResult> GetExternalLogin(string provider, string error = null)
        {
            if (error != null)
            {
                return Redirect(Url.Content("~/") + "#error=" + Uri.EscapeDataString(error));
            }

            if (!User.Identity.IsAuthenticated)
            {
                return new ChallengeResult(provider, this);
            }

            ExternalLoginData externalLogin = ExternalLoginData.FromIdentity(User.Identity as ClaimsIdentity);

            if (externalLogin == null)
            {
                return InternalServerError();
            }

            if (externalLogin.LoginProvider != provider)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                return new ChallengeResult(provider, this);
            }

            User user = await UserManager.FindAsync(new UserLoginInfo(externalLogin.LoginProvider,
                externalLogin.ProviderKey));

            bool hasRegistered = user != null;

            if (hasRegistered)
            {
                Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

                ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(UserManager,
                   OAuthDefaults.AuthenticationType);
                ClaimsIdentity cookieIdentity = await user.GenerateUserIdentityAsync(UserManager,
                    CookieAuthenticationDefaults.AuthenticationType);

                AuthenticationProperties properties = ApplicationOAuthProvider.CreateProperties(user.UserName);
                Authentication.SignIn(properties, oAuthIdentity, cookieIdentity);
            }
            else
            {
                IEnumerable<Claim> claims = externalLogin.GetClaims();
                ClaimsIdentity identity = new ClaimsIdentity(claims, OAuthDefaults.AuthenticationType);
                Authentication.SignIn(identity);
            }

            return Ok();
        }

        /// <summary>
        /// Get users (only if authorized)
        /// </summary>
        [Authorize(Roles="Admin")]
        [Route("users")]
        public IHttpActionResult GetUsers()
        {
            //Only SuperAdmin or Admin can delete users (Later when implement roles)
            var identity = User.Identity as System.Security.Claims.ClaimsIdentity;

            return Ok(this.AppUserManager.Users.ToList().Select(u => this.TheModelFactory.Create(u)));
        }

        /// <summary>
        /// Get user (only if authorized)
        /// </summary>
        [Route("user/{id:guid}", Name = "GetUserById")]
        public async Task<IHttpActionResult> GetUser(string Id)
        {
            //Only SuperAdmin or Admin can delete users (Later when implement roles)
            var user = await this.AppUserManager.FindByIdAsync(Id);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
            }

            return NotFound();

        }

        /// <summary>
        /// Get user by name (only if authorized)
        /// </summary>
        [Authorize(Roles = "Admin")]
        [Route("user/{username}")]
        public async Task<IHttpActionResult> GetUserByName(string username)
        {
            //Only SuperAdmin or Admin can delete users (Later when implement roles)
            var user = await this.AppUserManager.FindByNameAsync(username);

            if (user != null)
            {
                return Ok(this.TheModelFactory.Create(user));
            }

            return NotFound();

        }

        /// <summary>
        /// Register
        /// </summary>
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IHttpActionResult> Register(UserModel createUserModel)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var encryptor = new Encryption();
            string encryptedSecurityAnswer;
            string encryptedSecurityAnswerSalt;
            encryptor.Encrypt(ConfigurationManager.AppSettings["EncryptionPassword"],
                Convert.ToInt32(ConfigurationManager.AppSettings["EncryptionIterationCount"]), "Chairman Meow",
                out encryptedSecurityAnswerSalt, out encryptedSecurityAnswer);


            var securedPassword = new SecuredPassword(createUserModel.Password, _configuration.DefaultHashStrategy);


            var user = new User()
            {

                UserName = createUserModel.UserName,
                Email = createUserModel.UserName,
                FirstName = createUserModel.UserName,
                LastName = createUserModel.UserName,
                Approved = true,
                CreatedDateUtc = DateTime.UtcNow,
                EmailConfirmed = false,
                Enabled = true,
                HashStrategy = _configuration.DefaultHashStrategy,
                TelNoMobile = "07740101235",
                //PasswordHash = createUserModel.Password,//Convert.ToBase64String(securedPassword.Hash),
                PasswordLastChangedDateUtc = DateTime.UtcNow,
                PasswordSalt = createUserModel.Password,//Convert.ToBase64String(securedPassword.Salt),
                SecurityAnswer = encryptedSecurityAnswer,
                SecurityAnswerSalt = encryptedSecurityAnswerSalt,
                SecurityQuestionLookupItemId = 271,
                Title = "Mrs"
            };
            IdentityResult addUserResult = await this.AppUserManager.CreateAsync(user, createUserModel.Password);

           
            if (!addUserResult.Succeeded)
            {
                return GetErrorResult(addUserResult);
            }

            user = _context.User.First(u => u.UserName == user.UserName);
            string code = await this.AppUserManager.GenerateEmailConfirmationTokenAsync(user.Id.ToString());
            user.EmailConfirmationToken = code;

            // Email the user to complete the email verification process or inform them of a duplicate registration and would they like to change their password

            var callbackUrl = new Uri(Url.Link("ConfirmEmailRoute", new { userId = user.Id, code = code }));

            string emailBody;
            string emailSubject;
            emailSubject = $"{_configuration.ApplicationName} - Complete your registration";
            emailBody = "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>";

            _services.SendEmail(_configuration.DefaultFromEmailAddress, new List<string> { user.UserName }, null, null, emailSubject, emailBody, true);

            return Ok();
            /*
                        await this.AppUserManager.SendEmailAsync(user.Id.ToString(),
                                                                "Confirm your account",
                                                                "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");
                                                                */

        }

        /// <summary>
        /// Confirm Email
        /// </summary>
        [AllowAnonymous]
        [HttpGet]
        [Route("ConfirmEmail", Name = "ConfirmEmailRoute")]
        public async Task<IHttpActionResult> ConfirmEmail(string userId = "", string code = "")
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
            {
                ModelState.AddModelError("", "User Id and Code are required");
                return BadRequest(ModelState);
            }

            IdentityResult result = await this.AppUserManager.ConfirmEmailAsync(userId, code);

            User user = _context.User.First(u => u.Id == userId);

            if (result.Succeeded)
            {
                Uri locationHeader = new Uri(Url.Link("GetUserById", new { id = user.Id }));

                return Created(locationHeader, TheModelFactory.Create(user));
            }
            else
            {
                return GetErrorResult(result);
            }
        }

        /// <summary>
        /// Change Passoword
        /// </summary>
        [Authorize]
        [Route("ChangePassword")]
        public async Task<IHttpActionResult> ChangePassword(GlobalMessenger.Models.ChangePasswordBindingModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            IdentityResult result = await this.AppUserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);

            if (!result.Succeeded)
            {
                return GetErrorResult(result);
            }

            return Ok();
        }

        /// <summary>
        /// Delete user
        /// </summary>
        [Authorize(Roles = "Admin")]
        [Route("user/{id:guid}")]
        public async Task<IHttpActionResult> DeleteUser(string id)
        {

            //Only SuperAdmin or Admin can delete users (Later when implement roles)

            var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser != null)
            {
                IdentityResult result = await this.AppUserManager.DeleteAsync(appUser);

                if (!result.Succeeded)
                {
                    return GetErrorResult(result);
                }

                return Ok();

            }

            return NotFound();
          
        }

        /// <summary>
        /// Assign role
        /// </summary>
        [Authorize(Roles="Admin")]
        [Route("user/{id:guid}/roles")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignRolesToUser([FromUri] string id, [FromBody] string[] rolesToAssign)
        {

            var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser == null)
            {
                return NotFound();
            }
            
            var currentRoles = await this.AppUserManager.GetRolesAsync(appUser.Id.ToString());
            /*
            var rolesNotExists = rolesToAssign.Except(this.AppRoleManager.Roles.Select(x => x.Name)).ToArray();

            if (rolesNotExists.Count() > 0) {

                ModelState.AddModelError("", string.Format("Roles '{0}' does not exixts in the system", string.Join(",", rolesNotExists)));
                return BadRequest(ModelState);
            }

            IdentityResult removeResult = await this.AppUserManager.RemoveFromRolesAsync(appUser.Id.ToString(), currentRoles.ToArray());

            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove user roles");
                return BadRequest(ModelState);
            }
            */
            IdentityResult addResult = await this.AppUserManager.AddToRolesAsync(appUser.Id.ToString(), rolesToAssign);

            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add user roles");
                return BadRequest(ModelState);
            }

            return Ok();

        }

        /// <summary>
        /// Assign Claim
        /// </summary>
        [Authorize(Roles = "Admin")]
        [Route("user/{id:guid}/assignclaims")]
        [HttpPut]
        public async Task<IHttpActionResult> AssignClaimsToUser([FromUri] string id, [FromBody] List<ClaimBindingModel> claimsToAssign) {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

             var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser == null)
            {
                return NotFound();
            }

            foreach (ClaimBindingModel claimModel in claimsToAssign)
            {
                if (appUser.Claims.Any(c => c.ClaimType == claimModel.Type)) {
                   
                    await this.AppUserManager.RemoveClaimAsync(id, ExtendedClaimsProvider.CreateClaim(claimModel.Type, claimModel.Value));
                }

                await this.AppUserManager.AddClaimAsync(id, ExtendedClaimsProvider.CreateClaim(claimModel.Type, claimModel.Value));
            }
            
            return Ok();
        }

        /// <summary>
        /// Remove Claim
        /// </summary>
        [Authorize(Roles = "Admin")]
        [Route("user/{id:guid}/removeclaims")]
        [HttpPut]
        public async Task<IHttpActionResult> RemoveClaimsFromUser([FromUri] string id, [FromBody] List<ClaimBindingModel> claimsToRemove)
        {

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var appUser = await this.AppUserManager.FindByIdAsync(id);

            if (appUser == null)
            {
                return NotFound();
            }

            foreach (ClaimBindingModel claimModel in claimsToRemove)
            {
                if (appUser.Claims.Any(c => c.ClaimType == claimModel.Type))
                {
                    await this.AppUserManager.RemoveClaimAsync(id, ExtendedClaimsProvider.CreateClaim(claimModel.Type, claimModel.Value));
                }
            }

            return Ok();
        }

        private class ExternalLoginData
        {
            public string LoginProvider { get; set; }
            public string ProviderKey { get; set; }
            public string UserName { get; set; }

            public IList<Claim> GetClaims()
            {
                IList<Claim> claims = new List<Claim>();
                claims.Add(new Claim(ClaimTypes.NameIdentifier, ProviderKey, null, LoginProvider));

                if (UserName != null)
                {
                    claims.Add(new Claim(ClaimTypes.Name, UserName, null, LoginProvider));
                }

                return claims;
            }

            public static ExternalLoginData FromIdentity(ClaimsIdentity identity)
            {
                if (identity == null)
                {
                    return null;
                }

                Claim providerKeyClaim = identity.FindFirst(ClaimTypes.NameIdentifier);

                if (providerKeyClaim == null || String.IsNullOrEmpty(providerKeyClaim.Issuer)
                    || String.IsNullOrEmpty(providerKeyClaim.Value))
                {
                    return null;
                }

                if (providerKeyClaim.Issuer == ClaimsIdentity.DefaultIssuer)
                {
                    return null;
                }

                return new ExternalLoginData
                {
                    LoginProvider = providerKeyClaim.Issuer,
                    ProviderKey = providerKeyClaim.Value,
                    UserName = identity.FindFirstValue(ClaimTypes.Name)
                };
            }
        }

        private static class RandomOAuthStateGenerator
        {
            private static RandomNumberGenerator _random = new RNGCryptoServiceProvider();

            public static string Generate(int strengthInBits)
            {
                const int bitsPerByte = 8;

                if (strengthInBits % bitsPerByte != 0)
                {
                    throw new ArgumentException("strengthInBits must be evenly divisible by 8.", "strengthInBits");
                }

                int strengthInBytes = strengthInBits / bitsPerByte;

                byte[] data = new byte[strengthInBytes];
                _random.GetBytes(data);
                return HttpServerUtility.UrlTokenEncode(data);
            }
        }

        private IAuthenticationManager Authentication
        {
            get { return Request.GetOwinContext().Authentication; }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager2 ?? Request.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager2 = value;
            }
        }
    }
}