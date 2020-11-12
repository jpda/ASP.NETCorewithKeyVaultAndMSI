using System;
using Azure.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace ASPCoreWithKV
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, config) =>
                {
                    var builtConfig = config.Build();
                    config.AddAzureKeyVault(new Uri("https://cm-identity-kv.vault.azure.net"),
                            new ChainedTokenCredential(
                                new HybridManagedIdentityCredential(), // runs as local MSI via Arc
                                new ManagedIdentityCredential(), // runs as MSI in Azure
                                new AzureCliCredential())); // runs as me
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}