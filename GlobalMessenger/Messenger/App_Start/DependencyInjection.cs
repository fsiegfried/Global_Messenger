﻿using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
using GlobalMessenger.Model;
using SimpleInjector;
using SimpleInjector.Integration.Web;
using SimpleInjector.Integration.Web.Mvc;
using System.Reflection;
using System.Web.Mvc;
using Serilog;
using Serilog.Core;
using System.Web.Http;
using SimpleInjector.Integration.WebApi;
using GlobalMessengerAPI;
using GlobalMessengerAPI.Models;

namespace GlobalMessenger.App_Start
{
	public static class DependencyInjection
	{

		public static Container Container;

		public static void Configure()
		{
			// 1. Create a new Simple Injector container
			var container = new Container();
			container.Options.DefaultScopedLifestyle = new WebRequestLifestyle();

			container.RegisterMvcControllers(Assembly.GetExecutingAssembly());
			container.RegisterMvcIntegratedFilterProvider();
            container.RegisterWebApiControllers(GlobalConfiguration.Configuration);
            // 2. Configure the container (register)
           
            container.Register<IAppConfiguration, AppConfiguration>(Lifestyle.Singleton);     
            container.Register<IAppSensor, AppSensor>(Lifestyle.Scoped);
			container.Register<IAppUserStore<User>, UserStore<User>>(Lifestyle.Scoped);
			container.Register<IEncryption, Encryption>(Lifestyle.Scoped);
			container.Register<IFormsAuth, FormsAuth>(Lifestyle.Scoped);
			container.Register<IServices, GlobalMessenger.Core.Services>(Lifestyle.Scoped);
			container.Register<IRecaptcha, SecurityCheckRecaptcha>(Lifestyle.Scoped);
			container.Register<IUserIdentity, UserIdentity>(Lifestyle.Scoped);
			container.Register<IUserManager, AppUserManager>(Lifestyle.Scoped);
			container.Register<ISeContext, SeContext>(Lifestyle.Scoped);
			container.Register<IHttpCache, HttpCache>(Lifestyle.Scoped);

			// 3. Optionally verify the container's configuration.
			container.Verify();

			// 4. Register the container as MVC3 IDependencyResolver.
			DependencyResolver.SetResolver(new SimpleInjectorDependencyResolver(container));
			Container = container;

            GlobalConfiguration.Configuration.DependencyResolver = new SimpleInjectorWebApiDependencyResolver(container);

        }

    }

}