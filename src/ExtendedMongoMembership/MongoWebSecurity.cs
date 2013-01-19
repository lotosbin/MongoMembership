
using System;
using System.Web.Security;
using WebMatrix.WebData.Resources;
namespace ExtendedMongoMembership
{
    public static class MongoWebSecurity
    {
        public static bool Initialized { get; private set; }

        public static void Init(string userTableName, string userNameColumn)
        {
            if (!Initialized)
            {
                MongoMembershipProvider simpleMembership = Membership.Provider as MongoMembershipProvider;
                InitializeMembershipProvider(simpleMembership, userTableName, userNameColumn);

                MongoRoleProvider simpleRoleProvider = Roles.Provider as MongoRoleProvider;
                InitializeRoleProvider(simpleRoleProvider, userTableName, userNameColumn);

                Initialized = true;
            }
        }

        internal static void InitializeMembershipProvider(MongoMembershipProvider simpleMembership, string userTableName, string userNameColumn)
        {
            if (simpleMembership.InitializeCalled)
            {
                throw new InvalidOperationException(WebDataResources.Security_InitializeAlreadyCalled);
            }
            simpleMembership.UserNameColumn = userNameColumn;
            simpleMembership.UserTableName = userTableName;

            simpleMembership.InitializeCalled = true;
        }

        internal static void InitializeRoleProvider(MongoRoleProvider simpleRoles, string userTableName, string userNameColumn)
        {
            if (simpleRoles.InitializeCalled)
            {
                throw new InvalidOperationException(WebDataResources.Security_InitializeAlreadyCalled);
            }
            simpleRoles.InitializeCalled = true;
        }
    }
}
