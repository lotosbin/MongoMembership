using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using NavigationRoutes;
using ExtendedMongoMembership.Sample.Controllers;

namespace BootstrapMvcSample
{
    public class ExampleLayoutsRouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.MapNavigationRoute<AccessController>("Access Pages", c => c.Index())
                .AddChildRoute<AccessController>("Need Permission 1", c => c.Permission1())
                .AddChildRoute<AccessController>("Need Permission 2", c => c.Permission2())
                .AddChildRoute<AccessController>("Need Permission 3", c => c.Permission3());
        }
    }
}
