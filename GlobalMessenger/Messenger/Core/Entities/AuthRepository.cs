using GlobalMessenger.Entities;
using GlobalMessenger.Models;
using GlobalMessenger.Core;
using GlobalMessenger.Core.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace GlobalMessenger
{

    public class AuthRepository : IDisposable
    {
        private ISeContext _context;
        private SeContext _ctx;


        public AuthRepository()
        {
            
            _ctx = new SeContext();
        }


        public async Task<IdentityUser> FindUser(string userName, string password)
        {
            //IdentityUser user = await _userManager.FindAsync(userName, password);
            var user = await _ctx.User.SingleOrDefaultAsync(u => u.UserName == userName && u.Enabled && u.Approved && u.EmailConfirmed).ConfigureAwait(false);
            if (user == null) return null;
            if (password.Equals(user.PasswordSalt))
            {
                return user;
            }
            var securePassword = new SecuredPassword(password, Convert.FromBase64String(user.PasswordHash), Convert.FromBase64String(user.PasswordSalt), user.HashStrategy);
            if (securePassword.IsValid)
            {
                return user;
            }
            

            
            return null;
        }

        public Client FindClient(string clientId)
        {
            var client = _ctx.Clients.Find(clientId);

            return client;
        }

        public async Task<bool> AddRefreshToken(RefreshToken token)
        {

           var existingToken = _ctx.RefreshTokens.Where(r => r.Subject == token.Subject && r.ClientId == token.ClientId).SingleOrDefault();

           if (existingToken != null)
           {
             var result = await RemoveRefreshToken(existingToken);
           }
          
            _ctx.RefreshTokens.Add(token);

            return await _ctx.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveRefreshToken(string refreshTokenId)
        {
           var refreshToken = await _ctx.RefreshTokens.FindAsync(refreshTokenId);

           if (refreshToken != null) {
               _ctx.RefreshTokens.Remove(refreshToken);
               return await _ctx.SaveChangesAsync() > 0;
           }

           return false;
        }

        public async Task<bool> RemoveRefreshToken(RefreshToken refreshToken)
        {
            _ctx.RefreshTokens.Remove(refreshToken);
             return await _ctx.SaveChangesAsync() > 0;
        }

        public async Task<RefreshToken> FindRefreshToken(string refreshTokenId)
        {
            var refreshToken = await _ctx.RefreshTokens.FindAsync(refreshTokenId);

            return refreshToken;
        }

        public List<RefreshToken> GetAllRefreshTokens()
        {
             return  _ctx.RefreshTokens.ToList();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}