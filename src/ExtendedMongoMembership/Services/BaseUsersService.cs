using ExtendedMongoMembership.Entities;
using ExtendedMongoMembership.Services.Interfaces;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using MongoDB.Driver.Linq;
using System.Collections.Generic;
using System.Linq;

namespace ExtendedMongoMembership.Services
{
    public abstract class BaseUsersService<TDomain> : IBaseService<TDomain>
        where TDomain : MembershipAccountBase
    {
        protected virtual string GetCollectionName()
        {
            return "Users";
        }

        #region Member Vars

        private readonly string _databaseName;
        private string _connectionString;
        private readonly MongoDatabase _database;
        private MongoServer _server;
        private readonly MongoClient _client;

        #endregion

        #region Constructors

        public BaseUsersService(string connectionString)
        {
            _connectionString = connectionString;
            _databaseName = connectionString.Substring(connectionString.LastIndexOf('/') + 1);
            _client = new MongoClient(connectionString);
            _server = _client.GetServer();
            _database = _server.GetDatabase(_databaseName);
        }

        #endregion

        #region Public Methods

        public virtual TDomain GetById(dynamic id)
        {
            var collection = GetDefaultCollection();
            var item = collection.FindOneById(id);

            return item;
        }

        public virtual IEnumerable<TDomain> GetAll()
        {
            var collection = GetDefaultCollection();

            return collection.AsQueryable();
        }

        public virtual void Save(TDomain entity)
        {
            var collection = GetDefaultCollection();
            if (entity.UserId == 0)
            {
                int userId = 0;
                var session = new MongoSession(_connectionString);
                userId = session.GetNextSequence("user_id");

                entity.UserId = userId;
            }

            collection.Save(entity);
        }

        public virtual void Save(IEnumerable<TDomain> entities)
        {
            foreach (var entity in entities)
            {
                Save(entity);
            }
        }

        public void Delete(IEnumerable<TDomain> entities)
        {
            foreach (TDomain e in entities)
            {
                Delete(e);
            }
        }

        public void Delete(TDomain entity)
        {
            var collection = GetDefaultCollection();
            var query = Query.EQ("_id", entity.UserId);
            collection.Remove(query);
        }

        #endregion

        #region Helper Methods


        protected virtual MongoCollection<TDomain> GetDefaultCollection()
        {
            var collectionName = GetCollectionName();
            var collection = _database.GetCollection<TDomain>(collectionName);
            return collection;
        }

        #endregion


        public TDomain GetByName(string name)
        {
            return GetDefaultCollection().AsQueryable().FirstOrDefault(x => x.UserName == name);
        }
    }
}
