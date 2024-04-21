using Microsoft.AspNetCore.Identity;

namespace CustomIdentityWithJwt.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string FullName {  get; set; }   
        public string Address { get; set; }

        public string Role { get; set; }
    }
}
