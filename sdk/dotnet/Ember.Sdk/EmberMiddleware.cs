using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace Ember.Sdk
{
    public class EmberMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly EmberClient _client;

        public EmberMiddleware(RequestDelegate next, EmberClient client)
        {
            _next = next;
            _client = client;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context).ConfigureAwait(false);
                if (context.Response.StatusCode >= 500)
                {
                    await _client.CaptureMessageAsync("error", "http 5xx", new Dictionary<string, string>
                    {
                        { "method", context.Request.Method },
                        { "path", context.Request.Path },
                        { "status", context.Response.StatusCode.ToString() }
                    }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                await _client.CaptureErrorAsync(ex, new Dictionary<string, string>
                {
                    { "method", context.Request.Method },
                    { "path", context.Request.Path }
                }).ConfigureAwait(false);
                throw;
            }
        }
    }
}
