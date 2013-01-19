using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using MongoDB.Driver.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;


namespace ExtendedMongoMembership
{

    /*internal*/
    public class MongoSession : ISession
    {
        private MongoClient _client;
        private MongoServer _server;
        private MongoDatabase _provider;

        private string _connectionString = string.Empty;

        public MongoSession()
        {
            _connectionString = ConfigurationManager.ConnectionStrings["ConnectionString"].ConnectionString;
        }

        public MongoSession(string connectionString)
        {
            _connectionString = connectionString;
            _client = new MongoClient(_connectionString);
            _server = _client.GetServer();
            int last = _connectionString.LastIndexOf("/");
            _provider = _server.GetDatabase(_connectionString.Substring(last > -1 ? last + 1 : 0), WriteConcern.Acknowledged);
        }

        private MongoDatabase MongoDatabase { get { return this._provider; } }


        public IQueryable<MembershipAccount> Users
        {
            get { return _provider.GetCollection<MembershipAccount>("Users").AsQueryable(); }
        }

        public IQueryable<MembershipRole> Roles
        {
            get { return _provider.GetCollection<MembershipRole>("Roles").AsQueryable(); }
        }

        public IQueryable<OAuthToken> OAuthTokens
        {
            get { return _provider.GetCollection<OAuthToken>("OAuthTokens").AsQueryable(); }
        }

        #region IDisposable Members

        public void Dispose()
        {
            _server.Disconnect();
        }

        #endregion

        public void Add<T>(T item) where T : class
        {
            Type t = typeof(T);
            if (t == typeof(MembershipAccount))
            {
                var acc = item as MembershipAccount;
                acc.UserId = GetNextSequence("users");
                _provider.GetCollection<MembershipAccount>(GetCollectionName<MembershipAccount>()).Insert(acc);
            }
            else
            {
                _provider.GetCollection<T>(GetCollectionName<T>()).Insert(item);
            }
        }

        public void Add<T>(IEnumerable<T> items) where T : class
        {
            _provider.GetCollection<T>(GetCollectionName<T>()).Insert(items);
        }

        public void Save<T>(T item) where T : class
        {
            _provider.GetCollection<T>(GetCollectionName<T>()).Save(item);
        }

        public void Update<T>(T item) where T : class
        {
            Save(item);
        }

        public void DeleteByQuery<T>(IMongoQuery query) where T : class
        {
            _provider.GetCollection<T>(GetCollectionName<T>()).Remove(query);
        }

        public void DeleteById<T>(int id) where T : class
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection<T>(GetCollectionName<T>()).Remove(query);
        }

        public void DeleteById<T>(Guid id) where T : class
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection<T>(GetCollectionName<T>()).Remove(query);
        }

        public void DeleteById<T>(string id) where T : class
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection<T>(GetCollectionName<T>()).Remove(query);
        }

        public void DeleteById(object id, string collectionName)
        {
            IMongoQuery query = Query.EQ("_id", id.ToString());
            _provider.GetCollection(collectionName).Remove(query);
        }

        public void DeleteById(int id, string collectionName)
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection(collectionName).Remove(query);
        }

        public void DeleteById(Guid id, string collectionName)
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection(collectionName).Remove(query);
        }

        public void DeleteById(string id, string collectionName)
        {
            IMongoQuery query = Query.EQ("_id", id);
            _provider.GetCollection(collectionName).Remove(query);
        }

        public void Drop<T>()
        {

            var col = _provider.GetCollection<T>(GetCollectionName<T>());
            _provider.DropCollection(typeof(T).Name);
        }

        //public void CreateCappedCollection(string name)
        //{

        //    _provider.CreateCollection(name);
        //}

        private string GetCollectionName<T>()
        {
            string result = string.Empty;
            Type t = typeof(T);

            if (t == typeof(MembershipAccount))
            {
                result = "Users";
            }
            else if (t == typeof(MembershipRole))
            {
                result = "Roles";
            }
            else if (t == typeof(OAuthToken))
            {
                result = "OAuthTokens";
            }

            return result;
        }

        private int GetNextSequence(string name)
        {
            var collection = _provider.GetCollection("Counters");
            IMongoQuery query = Query.EQ("_id", name);
            var sortBy = SortBy.Descending("_id");
            IMongoUpdate update = MongoDB.Driver.Builders.Update.Inc("seq", 1);
            var result = collection.FindAndModify(query, sortBy, update, true, true);

            return int.Parse(result.ModifiedDocument[1].ToString());
        }

        public int GetUserId(string userTableName, string userNameColumn, string userName)
        {
            var collection = _provider.GetCollection(userTableName);
            IMongoQuery query = Query.EQ(userNameColumn, userName);
            var result = collection.FindOne(query);
            if (result == null)
                return -1;

            return result["_id"].AsInt32;
        }

        public bool CreateUserRow(string userName, string UserNameColumn, string userTableName, IDictionary<string, object> values)
        {
            List<BsonElement> elements = new List<BsonElement>();
            elements.Add(new BsonElement(UserNameColumn, userName));
            elements.Add(new BsonElement("_id", GetNextSequence(userTableName + "_id")));
            if (values != null)
            {
                foreach (var item in values)
                {
                    elements.Add(new BsonElement(item.Key, item.Value as BsonValue));
                }
            }

            var collection = _provider.GetCollection(userTableName);
            var result = collection.Insert(new BsonDocument(elements.ToArray()));
            return result.LastErrorMessage == null;
        }
    }

}
