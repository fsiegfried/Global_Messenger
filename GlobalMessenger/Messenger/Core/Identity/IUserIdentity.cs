using GlobalMessenger.Core.Constants;
using System.Web;
using System.Web.Mvc;

namespace GlobalMessenger.Core.Identity
{
    public interface IUserIdentity
    {
        string GetUserId(Controller controller);

        string GetUserName(Controller controller);

        bool IsUserInRole(Controller controller, string role);

		string GetClientIpAddress(HttpRequestBase request);

		Requester GetRequester(Controller controller, AppSensorDetectionPointKind? appSensorDetectionPointKind = null);
	    void RemoveAntiForgeryCookie(Controller controller);

    }
}