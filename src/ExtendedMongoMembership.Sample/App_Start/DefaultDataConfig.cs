using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using WebMatrix.WebData;

namespace ExtendedMongoMembership.Sample.App_Start {
    public static class DefaultDataConfig {
        public static void Populate() {
            string user1 = "user1", user2 = "user2", user3 = "user3", admin = "admin";

            if (!WebSecurity.UserExists(user1)) {
                WebSecurity.CreateUserAndAccount(user1, user1);
                if (!Roles.RoleExists(user1))
                    Roles.CreateRole(user1);

                Roles.AddUserToRole(user1, user1);
                PermissionsProvider.AssignPermissionsToRole(user1, Permissions.Permission1);
            }

            if (!WebSecurity.UserExists(user2)) {
                WebSecurity.CreateUserAndAccount(user2, user2);
                if (!Roles.RoleExists(user2))
                    Roles.CreateRole(user2);

                Roles.AddUserToRole(user2, user2);
                PermissionsProvider.AssignPermissionsToRole(user2, Permissions.Permission2);
            }

            if (!WebSecurity.UserExists(user3)) {
                WebSecurity.CreateUserAndAccount(user3, user3);
                if (!Roles.RoleExists(user3))
                    Roles.CreateRole(user3);

                Roles.AddUserToRole(user3, user3);
                PermissionsProvider.AssignPermissionsToRole(user3, Permissions.Permission3);
            }

            if (!WebSecurity.UserExists(admin)) {
                WebSecurity.CreateUserAndAccount(admin, admin);
                if (!Roles.RoleExists(admin))
                    Roles.CreateRole(admin);

                Roles.AddUserToRole(admin, admin);
                PermissionsProvider.AssignPermissionsToRole(admin, Permissions.Permission1, Permissions.Permission2, Permissions.Permission3);
            }
        }
    }
}