using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using GlobalMessenger.Model;

namespace GlobalMessenger.ViewModel
{
	public class ChatViewModel
	{

		public string Username { get; set; }

		public string LastAccountActivity { get; set; }

		public string UserId { get; set; }

        public string Password;

		public ChatViewModel(string username, UserLog lastAccountActivity, string userId, string password)
		{

			Username = username;
			LastAccountActivity = (lastAccountActivity != null ? lastAccountActivity.CreatedDateUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm") : "Never logged in");
			UserId = userId;
            Password = password;

		}
	}
}