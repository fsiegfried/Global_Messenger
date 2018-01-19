﻿using GlobalMessenger.Core;
using GlobalMessenger.Core.Attributes;
using GlobalMessenger.Core.Identity;
using Serilog;
using System;
using System.Web.Mvc;

namespace GlobalMessenger.Controllers
{
	[ExceptionHandler, AccountManagement]
	public abstract class SecurityControllerBase : Controller
	{

		public ILogger Logger;
		protected IUserIdentity UserIdentity;
		protected IAppSensor AppSensor;

		protected SecurityControllerBase(IUserIdentity userIdentity, IAppSensor appSensor)
		{
			Logger = Log.Logger;
			UserIdentity = userIdentity ?? throw new ArgumentNullException(nameof(userIdentity));
			AppSensor = appSensor ?? throw new ArgumentNullException(nameof(appSensor));

		}

		protected override void OnAuthorization(AuthorizationContext filterContext)
		{
			if (filterContext == null) throw new ArgumentNullException(nameof(filterContext));
			base.OnAuthorization(filterContext);
		}

	}
}