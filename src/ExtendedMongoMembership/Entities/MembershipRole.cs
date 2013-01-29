using MongoDB.Bson.Serialization.Attributes;
using System;

namespace ExtendedMongoMembership
{
    public class MembershipRole //: IRoleEntity
    {
        public MembershipRole()
        {
            RoleId = Guid.NewGuid();
        }

        [BsonId]
        public Guid RoleId { get; set; }
        public string RoleName { get; set; }
        public string LoweredRoleName { get; set; }
        public string Description { get; set; }
    }
}
