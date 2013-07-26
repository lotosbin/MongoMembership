using ExtendedMongoMembership.Sample.Models;
using ExtendedMongoMembership.Services.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Sample.Services
{
    public interface IUsersService : IBaseService<SampleUserProfile>
    {
    }
}
