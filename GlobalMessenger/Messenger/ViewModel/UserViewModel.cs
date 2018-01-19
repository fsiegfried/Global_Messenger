using System.Linq;
using GlobalMessenger.Core.Constants;
using GlobalMessenger.Model;

namespace GlobalMessenger.ViewModel
{

	public class UserViewModel
    {

		public bool IsAccessingUserAnAdmin { get; set; }
	    public bool IsCurrentUserAnAdmin { get; set; }
	    public User User { get; set; }
	    public bool IsOwnProfile { get; set; }

	    public UserViewModel(string currentUserId, bool isAccessingUserAnAdmin, User user)
	    {
		    IsOwnProfile = currentUserId.Equals(user.Id);
		    IsAccessingUserAnAdmin = isAccessingUserAnAdmin;
		    IsCurrentUserAnAdmin = user.UserRoles.Any(a => a.RoleId == Consts.Roles.Admin);
		    User = user;
	    }

	}
}