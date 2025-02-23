using Microsoft.AspNetCore.Identity;

namespace AuthProject.Data
{
    public class ApplicationUser:IdentityUser
    {
        public string Name {  get; set; }
    }
}
