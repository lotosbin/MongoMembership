using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace ExtendedMongoMembership
{
    [BsonIgnoreExtraElements]
    public class MembershipAccountBase
    {
        public MembershipAccountBase()
        {
            Roles = new List<MembershipRole>();
            Permissions = new List<string>();
        }

        [BsonId]
        public int UserId { get; set; }
        [BsonExtraElements]
        public BsonDocument CatchAll { get; set; }
        public string UserName { get; set; }

        public List<MembershipRole> Roles { get; set; }
        public List<string> Permissions { get; set; }
    }
}
