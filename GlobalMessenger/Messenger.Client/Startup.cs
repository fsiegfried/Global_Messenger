using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(GlobalMessenger.App_Start.Startup))]
namespace GlobalMessenger.App_Start
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
        }
    }
}