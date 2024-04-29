using Microsoft.AspNetCore.SignalR;

namespace BisleriumBlog.WebAPI.Helper
{
    public class SignalRHub : Hub
    {
        public async Task SendMessage()
        {
            // Broadcast a message to all clients
            await Clients.All.SendAsync("ReceiveMessage");
        }
    }
}
