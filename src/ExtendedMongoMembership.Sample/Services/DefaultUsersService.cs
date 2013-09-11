using ExtendedMongoMembership.Sample.Models;
using ExtendedMongoMembership.Services;

namespace ExtendedMongoMembership.Sample.Services
{
    public class DefaultUsersService : BaseUsersService<SampleUserProfile>, IUsersService
    {
        public DefaultUsersService(string connectionString)
            : base(connectionString)
        {

        }
    }
}