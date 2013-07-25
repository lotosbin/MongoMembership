using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace ExtendedMongoMembership
{
    [BsonIgnoreExtraElements]
    public class MembershipAccountBase
    {
        [BsonId]
        public int UserId { get; set; }
        [BsonExtraElements]
        public BsonDocument CatchAll { get; set; }
        public string UserName { get; set; }

        public List<MembershipRole> Roles { get; set; }
        public List<Guid> Permissions { get; set; }
    }
}
