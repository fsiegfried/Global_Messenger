using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Mvc;

namespace GlobalMessenger.ViewModel
{
    public class UsersViewModel
    {

        #region Declarations

		public string CurrentUserId { get; set; }

        #endregion

        #region Constructor

        public UsersViewModel(string currentUserId)            
        {
			CurrentUserId = currentUserId;
        }

        #endregion

    }
}