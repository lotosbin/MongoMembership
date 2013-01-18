using MongoDB.Bson.Serialization.Attributes;
using System;

namespace ExtendedMongoMembership
{
    public class MembershipRole //: IRoleEntity
    {
        public MembershipRole()
        {
            Id = Guid.NewGuid();
        }

        [BsonId]
        public Guid Id { get; set; }

        private string _roleName { get; set; }
        public string RoleName
        {
            get
            {
                return _roleName;
            }
            set
            {
                if (!string.IsNullOrEmpty(value))
                    LoweredRoleName = value.ToLower();
                _roleName = value;
            }
        }

        public string LoweredRoleName { get; set; }
        //public string Description { get; set; }
    }
}
