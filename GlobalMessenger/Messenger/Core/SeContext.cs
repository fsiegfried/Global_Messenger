using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Validation;
using GlobalMessenger.Entities;
using GlobalMessenger.Model;
using Microsoft.AspNet.Identity.EntityFramework;

namespace GlobalMessenger.Core
{
	public class SeContext : IdentityDbContext, ISeContext
    {
		public SeContext()
			: base("DefaultConnection")
		{
            Configuration.ProxyCreationEnabled = false;
            Configuration.LazyLoadingEnabled = false;
            Database.SetInitializer(new SeDatabaseIntialiser());
		}

        public static SeContext Create()
        {
            return new SeContext();
        }
        public DbSet<Log> Log { get; set; }
		public DbSet<LookupItem> LookupItem { get; set; }
		public DbSet<LookupType> LookupType { get; set; }
	    public DbSet<PreviousPassword> PreviousPassword { get; set; }
		public DbSet<Role> Role { get; set; }
		public DbSet<User> User { get; set; }
		public DbSet<UserLog> UserLog { get; set; }
	    public DbSet<UserRole> UserRole { get; set; }
        public DbSet<Message> Message { get; set; }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public void SetDeleted(object entity)
	    {
		    Entry(entity).State = EntityState.Deleted;
	    }
	    public void SetModified(object entity)
	    {
		    Entry(entity).State = EntityState.Modified;
	    }

	    public IEnumerable<DbValidationError> GetValidationErrors(object entity)
	    {
		    return Entry(entity).GetValidationResult().ValidationErrors;
	    }

	    public void SetConfigurationValidateOnSaveEnabled(bool isValidated)
	    {
		    Configuration.ValidateOnSaveEnabled = isValidated;
	    }


	}

}
