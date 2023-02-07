namespace WebApi.Authorization
{
    [AttributeUsage(AttributeTargets.Method)]
    public class AllowAnonymouseAttribute : Attribute
    {
    }
}
