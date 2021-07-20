using System.ComponentModel.DataAnnotations;

namespace API.Dto.Register
{
    public class AddRegisterDto
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password{ get; set; }
    }
}