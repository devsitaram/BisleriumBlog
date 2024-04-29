using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BisleriumBlog.Application.DTOs
{
    internal class UpdatePasswordRequestDTO
    {
        [Required(ErrorMessage = "User is must required")]
        public int OldPassword { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? NewPassword { get; set; }
    }
}
