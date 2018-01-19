using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
using System;
using System.Linq;
using System.Web.Http;

namespace GlobalMessengerAPI.Controller
{
    public class MessageController : ApiController
    {
        private readonly IAppConfiguration _configuration;
        private readonly ISeContext _context;
        private readonly IHttpCache _httpCache;
        private readonly IServices _services;
        private readonly IUserManager _userManager;

        public MessageController(IAppSensor appSensor, IAppConfiguration configuration, ISeContext context, IHttpCache httpCache, IUserIdentity userIdentity, IUserManager userManager, IServices services)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _httpCache = httpCache ?? throw new ArgumentNullException(nameof(httpCache));
            _services = services ?? throw new ArgumentNullException(nameof(services));
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }
        /// <summary>
        /// Get a specific Message or all (id=null) Massages 
        /// </summary>
        public IQueryable Get(int? id = null)
        {
            IQueryable message = null;

            if (id.HasValue)
            {
                message = from ms in _context.Message
                       where ms.Id == id
                       select new {ms.Id,ms.UserName,ms.Text};
            }
            else
            {
                message = from ms in _context.Message
                       select new { ms.Id, ms.UserName, ms.Text };
            }
            return message;

        }
        
    }
}