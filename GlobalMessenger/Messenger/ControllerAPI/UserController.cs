using System;
using System.Linq;
using System.Web.Http;
using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
namespace GlobalMessengerAPI.Controller
{
    public class UserController : ApiController
    {
        private readonly IAppConfiguration _configuration;
        private readonly ISeContext _context;
        private readonly IHttpCache _httpCache;
        private readonly IServices _services;
        private readonly IUserManager _userManager;

        public UserController(IAppSensor appSensor, IAppConfiguration configuration, ISeContext context, IHttpCache httpCache, IUserIdentity userIdentity, IUserManager userManager, IServices services)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _httpCache = httpCache ?? throw new ArgumentNullException(nameof(httpCache));
            _services = services ?? throw new ArgumentNullException(nameof(services));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }



        /// <summary>
        /// Get a specific User or all (id=null) Users 
        /// </summary>
        public IQueryable Get(string id = null)
        {
            IQueryable user = null;

            if (id == null)
            {
                user = from us in _context.User
                       where us.Id.Equals(id)
                       select new { us.Id, us.FirstName, us.LastName, us.UserName };
            }
            else
            {
                user = from us in _context.User
                       select new { us.Id, us.FirstName, us.LastName, us.UserName };
            }
                    return user;
                
        }

        
    }
}
