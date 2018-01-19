using GlobalMessenger.Core;
using GlobalMessenger.Core.Attributes;
using GlobalMessenger.Core.Identity;
using System;
using System.Linq;
using System.Web.Mvc;

namespace GlobalMessenger.Controllers
{
	[SeAuthorize(Roles = "Admin")]
	public class LogController : SecurityControllerBase
	{
		private readonly ISeContext _context;

		public LogController(ISeContext context, IUserIdentity userIdentity, IAppSensor appSensor) : base(userIdentity, appSensor)
		{
			_context = context ?? throw new ArgumentNullException(nameof(context));
		}

		[HttpGet]
		public ActionResult Index()
		{
			var logs = _context.Log.OrderByDescending(a => a.TimeStamp).Take(10).ToList();
			return View("Index", logs);
		}

	}
}