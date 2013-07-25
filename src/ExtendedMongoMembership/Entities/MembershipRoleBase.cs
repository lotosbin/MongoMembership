using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership
{
    [BsonIgnoreExtraElements]
    public class MembershipRoleBase : IEquatable<MembershipRole>
    {
        public MembershipRoleBase()
        {
            RoleId = Guid.NewGuid();
            Permissions = new List<Guid>();
        }

        [BsonId]
        public Guid RoleId { get; set; }
        public string RoleName { get; set; }
        public string LoweredRoleName { get; set; }

        public List<Guid> Permissions { get; set; }

        [BsonExtraElements]
        public BsonDocument CatchAll { get; set; }

        public bool Equals(MembershipRole other)
        {
            if (Object.ReferenceEquals(other, null)) return false;
            if (Object.ReferenceEquals(this, other)) return true;
            return RoleName.Equals(other.RoleName) && RoleId.Equals(other.RoleId);
        }

        public override int GetHashCode()
        {
            int hashRoleName = RoleName == null ? 0 : RoleName.GetHashCode();
            int hashRoleId = RoleId.GetHashCode();
            return hashRoleName ^ hashRoleId;
        }
    }
}
