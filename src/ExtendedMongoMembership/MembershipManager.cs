using ExtendedMongoMembership.Entities;
using MembershipPlus.Default;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;

namespace ExtendedMongoMembership
{
    public static class MembershipManager
    {
        public static bool Initialized { get; set; }

        static MembershipManager()
        {
            Initialized = false;
        }

        public static void Init(Type p, Type r, string connectionString = "")
        {
            if (!Initialized)
            {
                try
                {
                    if (string.IsNullOrEmpty(connectionString))
                    {
                        Membership.GetUser();
                        connectionString = MongoMembershipProvider.ConnectionString;
                    }

                    if (p != null)
                    {
                        InitializePermissions(p, connectionString);
                    }

                    if (r != null)
                    {
                        InitializeRoles(r, connectionString);
                    }
                    Initialized = true;
                }
                catch (Exception e)
                {
                }
            }
        }

        public static void InitializePermissions(Type p, string connectionString)
        {
            var session = new MongoSession(connectionString);
            List<MembershipPermission> permissions = new List<MembershipPermission>();
            List<string> dbPermission = session.Permissions.Select(x => x.Name).ToList();

            foreach (FieldInfo field in p.GetFields(BindingFlags.Static | BindingFlags.FlattenHierarchy | BindingFlags.Public))
            {
                string value = field.GetRawConstantValue().ToString();
                if (!dbPermission.Contains(value))
                {
                    session.Save(new MembershipPermission { Name = value });
                }
            }

        }

        public static void InitializeRoles(Type r, string connectionString)
        {
            var session = new MongoSession(connectionString);
            List<MembershipRole> roles = new List<MembershipRole>();
            List<MembershipPermission> permissions = session.Permissions.ToList();
            List<string> dbRoles = session.Roles.Select(x => x.RoleName).ToList();

            foreach (FieldInfo field in r.GetFields(BindingFlags.Static | BindingFlags.FlattenHierarchy | BindingFlags.Public))
            {
                string value = field.GetRawConstantValue().ToString();
                if (!dbRoles.Contains(value))
                {
                    MembershipRole role = new MembershipRole { RoleName = value };

                    if (value == DefaultRoles.Admin)
                    {
                        foreach (var p in permissions)
                        {
                            role.Permissions.Add(p.Name);
                        }
                    }

                    session.Save(role);
                }

            }
        }
    }
}
