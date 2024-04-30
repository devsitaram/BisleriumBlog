using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using BisleriumBlog.Application.Common.Interface;
using BisleriumBlog.Domain.Shared;
using BisleriumBlog.Domain.Entities;

namespace BisleriumBlog.Infrastructure.Data
{
    public class AppDbContext : IdentityDbContext
    {

        private readonly IDateTime _dateTime;

        public AppDbContext(DbContextOptions<AppDbContext> options, IDateTime dateTime) : base(options)
        {
            _dateTime = dateTime;
        }

        public DbSet<Blog> Blogs { get; set; }
        public DbSet<User> Users { get; set; }

       
        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken())
        {
            foreach (Microsoft.EntityFrameworkCore.ChangeTracking.EntityEntry<BaseEntity> entry in ChangeTracker.Entries<BaseEntity>())
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        entry.Entity.CreatedTime = _dateTime.Now;
                        break;

                    case EntityState.Modified:
                        entry.Entity.LastModifiedTime = _dateTime.Now;
                        break;
                }
            }

            var result = await base.SaveChangesAsync(cancellationToken);

            return result;
        }


        protected override void OnModelCreating(ModelBuilder builder)
        {
            var ADMIN_ID = "02174cf0–9412–4cfe-afbf-59f706d72cf6";
            var ROLE_ID = "341743f0-asd2–42de-afbf-59kmkkmk72cf6";

            // seed admin role
            builder.Entity<IdentityRole>().HasData(new IdentityRole
            {
                Name = "SuperAdmin",
                NormalizedName = "SUPERADMIN",
                Id = ROLE_ID,
                ConcurrencyStamp = ROLE_ID
            });

            //create user
            var appUser = new User
            {
                Id = ADMIN_ID,
                Email = "admin@gmail.com",
                EmailConfirmed = true,
                UserName = "ADMIN",
            };

            //set user password
            var ph = new PasswordHasher<User>();
            appUser.PasswordHash = ph.HashPassword(appUser, "Admin_12!");

            //seed user
            builder.Entity<User>().HasData(appUser);

            //set user role to admin
            builder.Entity<IdentityUserRole<string>>().HasData(new IdentityUserRole<string>
            {
                RoleId = ROLE_ID,
                UserId = ADMIN_ID
            });

            base.OnModelCreating(builder);
        }

    }
}
