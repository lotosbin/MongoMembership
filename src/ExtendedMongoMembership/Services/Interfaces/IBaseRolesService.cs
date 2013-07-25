using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Services.Interfaces
{
    public interface IBaseRolesService
    {
        MembershipRoleBase GetRoleById(Guid id);
        MembershipRoleBase GetRoleByRoleName(string roleName);
        IEnumerable<MembershipRoleBase> GetRoles();
        void Save(MembershipRoleBase entity);
        void Save(IEnumerable<MembershipRoleBase> entities);
        void Delete(IEnumerable<MembershipRoleBase> entities);
        void Delete(MembershipRoleBase entity);
    }
}
