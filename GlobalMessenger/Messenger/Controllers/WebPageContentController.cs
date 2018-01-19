using System.Web.Mvc;

namespace GlobalMessenger.Controllers
{
	public class WebPageContentController : Controller
	{

		[AllowAnonymous]
		public ViewResult TooManyRequests()
		{
			return View();
		}
	}
}