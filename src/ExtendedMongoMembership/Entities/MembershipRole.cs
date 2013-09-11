using ExtendedMongoMembership.Entities;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace ExtendedMongoMembership
{
    [BsonIgnoreExtraElements]
    public class MembershipRole : MembershipRoleBase
    {
        public string Description { get; set; }
    }
}
