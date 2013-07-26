using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;

using MembershipPlus.Default;
using ExtendedMongoMembership.Entities;

namespace ExtendedMongoMembership.Helpers.mvc
{
    public static class AuthorizeHelper
    {
        public static bool CheckUser(MembershipAccount user, IQueryable<MembershipRole> roles, IQueryable<MembershipPermission> permissionsQuery, string[] currentPermissions)
        {
            List<MembershipPermission> allPermissions = permissionsQuery.ToList();
            List<string> permissions = new List<string>();

            if (user == null)
            {
                var role = roles.FirstOrDefault(x => x.RoleName == DefaultRoles.Anonymous);
                if (role != null)
                    permissions = role.Permissions;
            }
            else
            {
                permissions = user
                    .Roles
                    .SelectMany(x => x.Permissions)
                    .ToList();
                permissions.AddRange(user.Permissions);
            }

            var currentPermissionEntities = allPermissions.Where(x => currentPermissions.Any(y => y == x.Name)).ToList();
            if (permissions.Any(x => currentPermissionEntities.FirstOrDefault(y => y.Name == x) != null))
            {
                return true;
            }
            else
            {
                return false;
            }

        }
    }
}
