using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MembershipPlus;
using ExtendedMongoMembership;
using ExtendedMongoMembership.Helpers.mvc;

namespace System.Security.Principal
{
    public static class PrincipalExtensions
    {
        public static bool HasPermission(this IPrincipal user, params string[] currentPermissions)
        {
            var session = new MongoSession(MongoMembershipProvider.ConnectionString);
            var userEntity = session.Users.FirstOrDefault(x => x.UserName == user.Identity.Name);
            return AuthorizeHelper.CheckUser(userEntity, session.Roles, session.Permissions, currentPermissions);
        }
    }
}
