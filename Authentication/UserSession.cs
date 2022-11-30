namespace BlazorServerAuthenticationAndAuthorization.Authentication
{
    public class UserSession
    {
        public string UserName { get; set; }
        public string Role { get; set; }
        public DateTime ExpiryTimeStamp { get; set; }
    }
}
