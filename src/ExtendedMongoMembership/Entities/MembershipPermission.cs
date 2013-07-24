using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Entities
{
    public class MembershipPermission
    {
        public MembershipPermission()
        {
            Id = Guid.NewGuid();
        }

        [BsonId]
        public Guid Id { get; set; }
        public string Name { get; set; }

        public bool Equals(MembershipPermission other)
        {
            if (Object.ReferenceEquals(other, null)) return false;
            if (Object.ReferenceEquals(this, other)) return true;
            return Name.Equals(other.Name) && Id.Equals(other.Id);
        }

        public override int GetHashCode()
        {
            int hashRoleName = Name == null ? 0 : Name.GetHashCode();
            int hashRoleId = Id.GetHashCode();
            return hashRoleName ^ hashRoleId;
        }
    }
}
