using System.ComponentModel.DataAnnotations;

namespace GlobalMessenger.ViewModel
{

    public class RecoverViewModel
    {
        [Required]
        [Display(Name = "Email Address")]
        public string UserName { get; set; }

        public bool HasRecaptcha { get; set; }

    }
}
