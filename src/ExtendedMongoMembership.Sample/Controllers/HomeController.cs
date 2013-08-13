using ExtendedMongoMembership.Sample.Services;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using WebMatrix.WebData;

namespace ExtendedMongoMembership.Sample.Controllers
{
    public class HomeController : Controller
    {
        private DefaultRolesService _rolesService;

        public HomeController()
        {
            /*var userName = Guid.NewGuid().ToString();

            WebSecurity.CreateUserAndAccount(userName, userName);
            _rolesService = new DefaultRolesService(ConfigurationManager.ConnectionStrings["mongodb"].ConnectionString);
            var role = _rolesService.CreateRole(Guid.NewGuid().ToString());
            PermissionsProvider.AssignPermissionsToRole(role.RoleId, Permissions.Permission1);

            var p = Roles.Provider as MongoRoleProvider;
            p.AddUsersToRoles(new string[] { userName }, role.RoleId);*/
        }

        public ActionResult Index()
        {
            return View();
        }

    }
}
