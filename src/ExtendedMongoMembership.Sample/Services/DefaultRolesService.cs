using ExtendedMongoMembership.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ExtendedMongoMembership.Sample.Services
{
    public class DefaultRolesService : BaseRolesService<MembershipRole>
    {
        public DefaultRolesService(string connString)
            : base(connString)
        {

        }

        public MembershipRole CreateRole(string name)
        {
            MembershipRole role = new MembershipRole { RoleName = name };

            GetDefaultCollection().Save(role);

            return role;
        }
    }
}