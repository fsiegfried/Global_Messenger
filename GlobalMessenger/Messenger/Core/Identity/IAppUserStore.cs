using Microsoft.AspNet.Identity;
using GlobalMessenger.Model;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GlobalMessenger.Core.Identity
{
	public interface IAppUserStore<T> : IUserStore<T, string>, IUserPasswordStore<T, string>, IDisposable where T : class, IUser<string>
	{

		Task<int> ChangePasswordAsync(string userId, string currentPassword, string newPassword);

		Task<LogonResult> TryLogOnAsync(string userName, string password);

		Task<ClaimsIdentity> CreateIdentityAsync(User user, string authenticationType);

		Task<IdentityResult> ChangePasswordFromTokenAsync(string userId, string passwordResetToken, string newPassword);
		Task<IdentityResult> ResetPasswordAsync(string userId, string newPassword, string actioningUserName);
	}
}