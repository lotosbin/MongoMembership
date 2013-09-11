using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace ExtendedMongoMembership.Sample.Controllers
{
    public class AccessController : Controller
    {
        //
        // GET: /Access/

        public ActionResult Index()
        {
            return View();
        }

        [Access(Permissions.Permission1)]
        public ActionResult Permission1()
        {
            return View();
        }

        [Access(Permissions.Permission2)]
        public ActionResult Permission2()
        {
            return View();
        }

        [Access(Permissions.Permission3)]
        public ActionResult Permission3()
        {
            return View();
        }
    }
}
