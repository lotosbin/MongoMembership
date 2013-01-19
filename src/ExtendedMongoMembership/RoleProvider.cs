using System;
using System.Collections.Generic;
using System.Configuration.Provider;
using System.Globalization;
using System.Linq;
using System.Web.Security;
using WebMatrix.WebData.Resources;

namespace ExtendedMongoMembership
{
    public class MongoRoleProvider : RoleProvider
    {
        private RoleProvider _previousProvider;

        public MongoRoleProvider()
            : this(null)
        {
        }

        public MongoRoleProvider(RoleProvider previousProvider)
        {
            _previousProvider = previousProvider;
        }

        private RoleProvider PreviousProvider
        {
            get
            {
                if (_previousProvider == null)
                {
                    throw new InvalidOperationException(WebDataResources.Security_InitializeMustBeCalledFirst);
                }
                else
                {
                    return _previousProvider;
                }
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string ApplicationName
        {
            get
            {
                if (InitializeCalled)
                {
                    throw new NotSupportedException();
                }
                else
                {
                    return PreviousProvider.ApplicationName;
                }
            }
            set
            {
                if (InitializeCalled)
                {
                    throw new NotSupportedException();
                }
                else
                {
                    PreviousProvider.ApplicationName = value;
                }
            }
        }

        internal bool InitializeCalled { get; set; }

        private string _connectionString;

        internal virtual ISession ConnectToDatabase(string connectionString)
        {
            return new MongoSession(connectionString);
        }

        private void VerifyInitialized()
        {
            if (!InitializeCalled)
            {
                throw new InvalidOperationException(WebDataResources.Security_InitializeMustBeCalledFirst);
            }
        }
        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            string temp = config["connectionStringName"];

            if (string.IsNullOrEmpty(temp))
                throw new ProviderException(StringResources.GetString(StringResources.Connection_name_not_specified));

            _connectionString = SecUtility.GetConnectionString(temp, true, true);

            if (string.IsNullOrEmpty(_connectionString))
            {
                throw new ProviderException(StringResources.GetString(StringResources.Connection_string_not_found, temp));
            }

            base.Initialize(name, config);
        }

        private List<MembershipAccount> GetUsersFromNames(ISession session, string[] usernames)
        {
            List<MembershipAccount> users = new List<MembershipAccount>(usernames.Length);
            foreach (string username in usernames)
            {
                var user = MongoMembershipProvider.GetUser(session, username);
                users.Add(user);
            }
            return users;
        }

        private static List<MembershipRole> GetRolesFromNames(ISession session, string[] roleNames)
        {
            List<MembershipRole> roles = new List<MembershipRole>(roleNames.Length);
            foreach (string role in roleNames)
            {
                MembershipRole r = FindRole(session, role);
                if (r == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.SimpleRoleProvider_NoRoleFound, role));
                }
                roles.Add(r);
            }
            return roles;
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            if (!InitializeCalled)
            {
                PreviousProvider.AddUsersToRoles(usernames, roleNames);
            }
            else
            {
                using (var session = ConnectToDatabase(_connectionString))
                {
                    int userCount = usernames.Length;
                    int roleCount = roleNames.Length;
                    List<MembershipAccount> users = GetUsersFromNames(session, usernames);
                    List<MembershipRole> roles = GetRolesFromNames(session, roleNames);

                    // Generate a INSERT INTO for each userid/rowid combination, where userIds are the first params, and roleIds follow
                    for (int uId = 0; uId < userCount; uId++)
                    {
                        for (int rId = 0; rId < roleCount; rId++)
                        {
                            if (IsUserInRole(usernames[uId], roleNames[rId]))
                            {
                                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.SimpleRoleProvder_UserAlreadyInRole, usernames[uId], roleNames[rId]));
                            }
                            var user = users[uId];
                            user.Roles.Add(roles[rId]);
                            try
                            {
                                session.Save(user);
                            }
                            catch (Exception e)
                            {
                                throw new ProviderException(WebDataResources.Security_DbFailure);
                            }
                        }
                    }
                }
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override void CreateRole(string roleName)
        {
            if (!InitializeCalled)
            {
                PreviousProvider.CreateRole(roleName);
            }
            else
            {
                using (var session = ConnectToDatabase(_connectionString))
                {
                    var role = FindRole(session, roleName);
                    if (role != null)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, WebDataResources.SimpleRoleProvider_RoleExists, roleName));
                    }

                    MembershipRole newRole = new MembershipRole
                    {
                        RoleName = roleName
                    };

                    try
                    {
                        session.Save(newRole);
                    }
                    catch (Exception e)
                    {
                        throw new ProviderException(WebDataResources.Security_DbFailure);
                    }
                }
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.DeleteRole(roleName, throwOnPopulatedRole);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                var role = FindRole(session, roleName);
                if (role == null)
                {
                    return false;
                }

                if (throwOnPopulatedRole)
                {
                    int usersInRole = session.Users.Where(x => x.Roles.Any(y => y.Id == role.Id)).Count();

                    if (usersInRole > 0)
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, WebDataResources.SimpleRoleProvder_RolePopulated, roleName));
                    }
                }
                else
                {
                    // Delete any users in this role first
                    session.DeleteById<MembershipRole>(role.Id);
                }

                try
                {
                    foreach (var usr in session.Users.Where(x => x.Roles.Any(y => y.Id == role.Id)).ToList())
                    {
                        usr.Roles = usr.Roles.Where(x => x.Id != role.Id).ToList();
                        session.Save(usr);
                    }
                    return true;
                }
                catch (Exception e)
                {
                    return false;
                }
                //return (rows == 1); // REVIEW: should this ever be > 1?
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.FindUsersInRole(roleName, usernameToMatch);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                // REVIEW: Is there any way to directly get out a string[]?
                List<MembershipAccount> result = session
                    .Users
                    .ToList()
                    .Where(y => y.Roles.Any(x => x.RoleName == roleName) &&
                        y.UserName.Contains(usernameToMatch))
                    .ToList();

                string[] users = new string[result.Count];
                for (int i = 0; i < result.Count; i++)
                {
                    users[i] = result[i].UserName;
                }
                return users;
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string[] GetAllRoles()
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetAllRoles();
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                return session.Roles.Select(x => x.RoleName).ToArray();
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string[] GetRolesForUser(string username)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetRolesForUser(username);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                var user = MongoMembershipProvider.GetUser(session, username);
                if (user == null)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.Security_NoUserFound, username));
                }

                return user.Roles.Select(x => x.RoleName).ToArray();
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string[] GetUsersInRole(string roleName)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetUsersInRole(roleName);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                return session
                    .Users
                    .Where(x => x.Roles.Any(y => y.RoleName == roleName))
                    .Select(x => x.UserName)
                    .ToArray();
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool IsUserInRole(string username, string roleName)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.IsUserInRole(username, roleName);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                var usr = session.Users.FirstOrDefault(x => x.Roles.Any(y => y.RoleName == roleName) && x.UserName == username);
                return (usr != null);
            }
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            if (!InitializeCalled)
            {
                PreviousProvider.RemoveUsersFromRoles(usernames, roleNames);
            }
            else
            {
                foreach (string rolename in roleNames)
                {
                    if (!RoleExists(rolename))
                    {
                        throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.SimpleRoleProvider_NoRoleFound, rolename));
                    }
                }

                foreach (string username in usernames)
                {
                    foreach (string rolename in roleNames)
                    {
                        if (!IsUserInRole(username, rolename))
                        {
                            throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, WebDataResources.SimpleRoleProvder_UserNotInRole, username, rolename));
                        }
                    }
                }

                using (var session = ConnectToDatabase(_connectionString))
                {
                    List<MembershipAccount> users = GetUsersFromNames(session, usernames);

                    foreach (var user in users)
                    {
                        foreach (var role in roleNames)
                        {
                            user.Roles = user
                                .Roles
                                .Where(x => x.RoleName != role)
                                .ToList();
                        }

                        try
                        {
                            session.Save(user);
                        }
                        catch (Exception e)
                        {
                            throw new ProviderException(WebDataResources.Security_DbFailure);
                        }
                    }
                }
            }
        }

        private static MembershipRole FindRole(ISession session, string roleName)
        {
            return session.Roles.FirstOrDefault(x => x.RoleName == roleName);
        }

        // Inherited from RoleProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool RoleExists(string roleName)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.RoleExists(roleName);
            }
            using (var session = ConnectToDatabase(_connectionString))
            {
                return (FindRole(session, roleName) != null);
            }
        }


    }

}
