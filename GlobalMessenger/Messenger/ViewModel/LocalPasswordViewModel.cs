using System.ComponentModel.DataAnnotations;

namespace GlobalMessenger.ViewModel
{
    public class LocalPasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
		[StringLength(100, ErrorMessage = "The {0} must be at least {2} and less than {1} characters long.", MinimumLength = 6)]
		public string OldPassword { get; set; }

        [Required]
		[StringLength(100, ErrorMessage = "The {0} must be at least {2} and less than {1} characters long.", MinimumLength = 6)]
		[DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}