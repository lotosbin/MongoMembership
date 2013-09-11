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
        [BsonId]
        public string Name { get; set; }

        public bool Equals(MembershipPermission other)
        {
            if (Object.ReferenceEquals(other, null)) return false;
            if (Object.ReferenceEquals(this, other)) return true;
            return Name.Equals(other.Name);
        }

        public override int GetHashCode()
        {
            int hashPermissionName = Name == null ? 0 : Name.GetHashCode();
            return hashPermissionName;
        }
    }
}
