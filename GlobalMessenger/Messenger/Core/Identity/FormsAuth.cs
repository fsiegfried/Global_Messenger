using System.Web.Security;

namespace GlobalMessenger.Core.Identity
{
    public class FormsAuth : IFormsAuth
    {

        public void SignOut()
        {
            FormsAuthentication.SignOut();
        }

    }
}