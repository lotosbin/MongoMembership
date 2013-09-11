using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Principal;
using System.Web.Security;
using ExtendedMongoMembership.Helpers.mvc;
using ExtendedMongoMembership;
using ExtendedMongoMembership.Entities;

namespace System.Web.Mvc
{
    public class AccessAttribute : AuthorizeAttribute
    {
        private MongoSession _session;
        private string[] _permissions;
        public string[] Permissions
        {
            get { return _permissions ?? new string[0]; }
            set { _permissions = value; }
        }

        public AccessAttribute(params string[] permissions)
        {
            Membership.GetUser();

            _permissions = permissions;
            _session = new MongoSession(MongoMembershipProvider.ConnectionString);
        }

        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            var actionAttributes = filterContext.ActionDescriptor.GetCustomAttributes(typeof(AccessAttribute), true);

            if (actionAttributes.Length > 0)
            {
                var notSkipAuthorization = actionAttributes.Any(x => this.GetType() == x.GetType());
                if (notSkipAuthorization)
                {
                    base.OnAuthorization(filterContext);

                    if (filterContext.Result is HttpUnauthorizedResult)
                    {
                        string returnUrl = string.Empty;
                        if (filterContext.HttpContext.Request.UrlReferrer != null)
                        {
                            returnUrl = filterContext.HttpContext.Request.UrlReferrer.PathAndQuery;
                            returnUrl = filterContext.HttpContext.Server.UrlEncode(returnUrl);
                        }
                        filterContext.Result = new RedirectResult("~/Error/Authorization?t=NoPermission");
                    }
                }
            }
            else
            {
                base.OnAuthorization(filterContext);

                if (filterContext.Result is HttpUnauthorizedResult)
                    filterContext.Result = new RedirectResult("~/Error/Authorization?t=NoPermission");
            }

        }

        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            if (httpContext == null)
                throw new ArgumentNullException("httpContext");

            if (Permissions.Length == 0)
            {
                return base.AuthorizeCore(httpContext);
            }
            else
            {
                var provs = Membership.Providers;

                return AuthorizeHelper.CheckUser(GetUser(httpContext.User), GetAllRoles(), GetAllPermissions(), _permissions);
            }
        }

        public virtual IQueryable<MembershipPermission> GetAllPermissions()
        {
            return _session.Permissions.AsQueryable();
        }

        public virtual IQueryable<MembershipRole> GetAllRoles()
        {
            return _session.Roles.AsQueryable();
        }

        public virtual MembershipAccount GetUser(IPrincipal user)
        {
            if (user.Identity.IsAuthenticated)
            {
                return _session.Users.AsQueryable().FirstOrDefault(x => x.UserName == user.Identity.Name);
            }
            return null;
        }
    }
}