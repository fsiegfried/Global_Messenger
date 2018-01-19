using System.Web.Mvc;

namespace GlobalMessenger.Core
{
    public interface IRecaptcha
    {
        bool ValidateRecaptcha(Controller controller);
    }
}