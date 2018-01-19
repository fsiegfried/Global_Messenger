using System.ComponentModel.DataAnnotations;

namespace GlobalMessenger.ViewModel
{
    public class RegisterExternalLogOnViewModel
    {
        [Required]
        [Display(Name = "User name")]
        public string UserName { get; set; }

        public string ExternalLogOnData { get; set; }
    }
}