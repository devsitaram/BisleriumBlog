using System.ComponentModel.DataAnnotations;
using BisleriumBlog.Domain.Shared;


namespace BisleriumBlog.Domain.Entities
{
    public class Blog : BaseEntity
    {
        [Key]
        public int BlogId { get; set; }

        [Required]
        public string Title { get; set; }

        [Required]
        public string Content { get; set; }

        [Display(Name = "Image URL")]
        public string ImageUrl { get; set; }

        public int VoteConut { get; set; }

        // Foreign key
        public string UserId { get; set; }
        public virtual User User { get; set; }
    }
}
