using GlobalMessenger.Model;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace GlobalMessenger.Core.Identity
{
	public interface IUserManager
    {
	    Task<SeIdentityResult> CreateAsync(string userName, string firstName, string lastName, string password, string passwordConfirmation, int securityQuestionLookupItemId, string securityAnswer);
	    Task<string> LogOnAsync(string userName, bool isPersistent);
	    Task<LogonResult> TryLogOnAsync(string userName, string password);
	    Task<User> FindUserByIdAsync(string userId);
	    void SignOut();
	    Task<SeIdentityResult> ChangePasswordAsync(string userId, string oldPassword, string newPassword);
	    Task<SeIdentityResult> ChangePasswordFromTokenAsync(string userId, string token, string newPassword);
	    Task<SeIdentityResult> ResetPasswordAsync(string userId, string actioningUserName);
	    SeIdentityResult ValidatePassword(User user, string password, List<string> bannedWords);

	}
}
