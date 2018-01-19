﻿namespace GlobalMessenger.Core.Constants
{
	public static class Consts
	{
		public static class LookupTypeId
		{
			public static int BadPassword = 1;
			public static int SecurityQuestion = 2;
		}
		public static class Roles
		{
			public static int Admin = 1;
		}

		public static class UserManagerMessages
		{
			public static string PasswordValidityMessage = "Your password must consist of 8 characters, digits or special characters and must contain at least 1 uppercase, 1 lowercase and 1 numeric value";
		}
	}
}