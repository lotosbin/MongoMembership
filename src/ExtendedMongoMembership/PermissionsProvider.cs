using ExtendedMongoMembership.Entities;
using ExtendedMongoMembership.Helpers;
using System;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership
{
    public static class PermissionsProvider
    {
        private static List<MembershipPermission> _allPermissions;
        private static DateTime _lastCacheUpdate;
        private static MongoSession _session;

        public static int MinutesToRefreshCache { get; set; }

        static PermissionsProvider()
        {
            MinutesToRefreshCache = 5;
            _session = new MongoSession(MongoMembershipProvider.ConnectionString);
        }

        public static List<MembershipPermission> GetAllPermissions(bool useCache = true)
        {
            var connString = MongoMembershipProvider.ConnectionString;

            if (useCache && _lastCacheUpdate.AddMinutes(MinutesToRefreshCache) > DateTime.Now && _allPermissions.Count > 0)
            {

            }
            else
            {
                _allPermissions = _session.Permissions.ToList();
                _lastCacheUpdate = DateTime.Now;
            }

            return _allPermissions;
        }

        public static MembershipPermission CreatePermission(string name)
        {
            MembershipPermission permission = _session.Permissions.FirstOrDefault(x => x.Name == name);

            if (permission == null)
            {
                permission = new MembershipPermission
                {
                    Name = name
                };

                _session.Add<MembershipPermission>(permission);
            }

            return permission;
        }

        public static bool DeletePermission(string name, bool throwException = true)
        {
            MembershipPermission permission = _session.Permissions.FirstOrDefault(x => x.Name == name);
            var rolesWithPermissionCount = _session.Roles.Where(x => x.Permissions.Any(y => y == permission.Id)).Count();
            var usersWithPermissionCount = _session.Users.Where(x => x.Permissions.Any(y => y == permission.Id)).Count();

            if (permission != null && rolesWithPermissionCount == 0 && usersWithPermissionCount == 0)
            {
                _session.DeleteById<MembershipPermission>(permission.Id);

                return true;
            }

            if (throwException)
            {
                throw new ProviderException("Permission is not empty");
            }

            return false;
        }

        public static void AssignPermissionsToRole(string roleName, params string[] permissionsArray)
        {
            SecUtility.CheckArrayParameter(ref permissionsArray, true, true, true, 256, "permissions");
            SecUtility.CheckParameter(ref roleName, true, false, true, 256, "roleName");

            try
            {
                List<string> _permissions = permissionsArray.ToList();

                var permissions = (from p in _session.Permissions
                                   where _permissions.Contains(p.Name)
                                   select p).ToList();

                var role = _session.Roles.FirstOrDefault(x => x.RoleName == roleName);
                var usersInRole = _session.Users.Where(x => x.Roles.Any(y => y.RoleName == roleName)).ToList();


                foreach (var perm in permissions)
                {
                    if (perm != null)
                    {
                        if (!role.Permissions.Contains(perm.Id))
                        {
                            role.Permissions.Add(perm.Id);

                            foreach (var user in usersInRole)
                            {
                                var roleToChange = user.Roles.FirstOrDefault(x => x.RoleName == role.RoleName);
                                roleToChange.Permissions.Add(perm.Id);
                            }
                        }
                    }
                }
                _session.Save(role);
                foreach (var user in usersInRole)
                {
                    _session.Save(user);
                }

            }
            catch
            {
                throw;
            }
        }

        public static void RemovePermissionsFromRole(string roleName, string[] permissionsArray)
        {
            SecUtility.CheckArrayParameter(ref permissionsArray, true, true, true, 256, "permissions");
            SecUtility.CheckParameter(ref roleName, true, false, true, 256, "roleName");

            try
            {
                List<string> _permissions = permissionsArray.ToList();

                var permissions = (from p in _session.Permissions
                                   where _permissions.Contains(p.Name)
                                   select p).ToList();

                var role = _session.Roles.FirstOrDefault(x => x.RoleName == roleName);
                var usersInRole = _session.Users.Where(x => x.Roles.Any(y => y.RoleName == roleName)).ToList();


                foreach (var perm in permissions)
                {
                    if (perm != null)
                    {
                        if (role.Permissions.Contains(perm.Id))
                        {
                            role.Permissions.Remove(perm.Id);

                            foreach (var user in usersInRole)
                            {
                                var roleToChange = user.Roles.FirstOrDefault(x => x.RoleName == role.RoleName);
                                roleToChange.Permissions.Remove(perm.Id);
                            }
                        }
                    }
                }
                _session.Save(role);
                foreach (var user in usersInRole)
                {
                    _session.Save(user);
                }

            }
            catch
            {
                throw;
            }
        }
    }
}
