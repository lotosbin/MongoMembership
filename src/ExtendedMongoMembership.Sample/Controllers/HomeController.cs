using System.Web.Mvc;

namespace ExtendedMongoMembership.Sample.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            //MongoWebSecurity.Init("UserProfiles", "UserName");
            //Roles.CreateRole("Administrator");
            //Roles.CreateRole("User");
            //Roles.DeleteRole("User", false);
            //Roles.AddUserToRole("admin", "Administrator");
            //Roles.AddUserToRole("admin", "User");


            ViewBag.Message = "Modify this template to jump-start your ASP.NET MVC application.";

            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your app description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}
