using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Validation;
using GlobalMessenger.Model;
using System.Threading.Tasks;

namespace GlobalMessenger.Core
{
    public interface ISeContext
    {
	    DbSet<Log> Log { get; set; }
		DbSet<LookupItem> LookupItem { get; set; }
        DbSet<LookupType> LookupType { get; set; }
	    DbSet<PreviousPassword> PreviousPassword { get; set; }
		DbSet<Role> Role { get; set; }
        DbSet<User> User { get; set; }
        DbSet<UserLog> UserLog { get; set; }
	    DbSet<UserRole> UserRole { get; set; }
        DbSet<Message> Message { get; set; }

        IEnumerable<DbValidationError> GetValidationErrors(object entity);
		int SaveChanges();
        Task<int> SaveChangesAsync();
	    void SetDeleted(object entity);
		void SetModified(object entity);
		void SetConfigurationValidateOnSaveEnabled(bool isValidated);
        void Dispose();
    }
}