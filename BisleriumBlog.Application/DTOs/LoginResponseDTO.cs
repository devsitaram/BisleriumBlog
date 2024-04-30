using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BisleriumBlog.Application.DTOs
{
    public class LoginResponseDTO
    {
        public bool? Status { get; set; }
        public string? Message { get; set; }
        public string? AccessToken { get; set; }
    }
}
