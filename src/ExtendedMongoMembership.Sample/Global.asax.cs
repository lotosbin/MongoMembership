using ExtendedMongoMembership.Sample.App_Start;
using System.Configuration;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace ExtendedMongoMembership.Sample
{
    // Note: For instructions on enabling IIS6 or IIS7 classic mode, 
    // visit http://go.microsoft.com/?LinkId=9394801

    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();

            WebApiConfig.Register(GlobalConfiguration.Configuration);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
            AuthConfig.RegisterAuth();
            BootstrapSupport.BootstrapBundleConfig.RegisterBundles(System.Web.Optimization.BundleTable.Bundles);
            BootstrapMvcSample.ExampleLayoutsRouteConfig.RegisterRoutes(RouteTable.Routes);

            RouteConfig.RegisterRoutes(RouteTable.Routes);

            MembershipManager.Init(typeof(Permissions), null, ConfigurationManager.ConnectionStrings["mongodb"].ConnectionString);
            DefaultDataConfig.Populate();
        }
    }
}