using Microsoft.AspNetCore.Builder;

namespace Ember.Sdk
{
    public static class EmberMiddlewareExtensions
    {
        public static IApplicationBuilder UseEmber(this IApplicationBuilder app, EmberClient client)
        {
            return app.UseMiddleware<EmberMiddleware>(client);
        }
    }
}
