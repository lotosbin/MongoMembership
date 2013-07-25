using ExtendedMongoMembership.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Services
{
    public interface IUserProfileServiceBase
    {
        MembershipAccountBase GetProfileById(int id);
        MembershipAccountBase GetProfileByUserName(string userName);
        IEnumerable<MembershipAccountBase> GetAllProfiles();
        void CreateProfile(MembershipAccountBase entity);
        void UpdateProfile(MembershipAccountBase entity);
        void Delete(IEnumerable<MembershipAccountBase> entities);
        void DeleteProfile(MembershipAccountBase entity);
    }
}
