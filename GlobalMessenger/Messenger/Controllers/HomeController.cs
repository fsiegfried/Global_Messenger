using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
using System.Web.Mvc;

namespace GlobalMessenger.Controllers
{
	public class HomeController : SecurityControllerBase
	{
		
		public HomeController(IUserIdentity userIdentity, IAppSensor appSensor) : base (userIdentity, appSensor)
		{

		}

		public ActionResult Index()
		{
			ViewBag.Message = "Global Messenger";
			return View("Index");
		}

		public ActionResult About()
		{
			ViewBag.Message = "";
			return View("About");
		}

		public ActionResult Contact()
		{
			ViewBag.Message = "Your contact page.";
			return View("Contact");
		}

        public ActionResult LoginApi()
        {
            ViewBag.Message = "Login via API";
            return View("LoginApi");
        }



    }
}
