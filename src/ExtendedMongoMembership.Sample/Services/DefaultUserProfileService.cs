using ExtendedMongoMembership.Sample.Models;
using ExtendedMongoMembership.Services;

namespace ExtendedMongoMembership.Sample.Services
{
    public class DefaultUserProfileService : UserProfileService<SampleUserProfile>
    {
        public DefaultUserProfileService(string connectionString)
            : base(connectionString)
        {

        }

        protected override string GetCollectionName()
        {
            return "Users";
        }
    }
}