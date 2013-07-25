﻿using ExtendedMongoMembership.Entities;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using MongoDB.Driver.Linq;
using System.Collections.Generic;
using System.Linq;

namespace ExtendedMongoMembership.Services
{
    public abstract class UserProfileServiceBase : IUserProfileServiceBase
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

        public UserProfileServiceBase(string connectionString)
        {
            _connectionString = connectionString;
            _databaseName = connectionString.Substring(connectionString.LastIndexOf('/') + 1);
            _client = new MongoClient(connectionString);
            _server = _client.GetServer();
            _database = _server.GetDatabase(_databaseName);
        }

        #endregion

        #region Public Methods

        public virtual MembershipAccountBase GetProfileById(int id)
        {
            var collection = GetDefaultCollection();
            var item = collection.FindOneById(id);

            return item;
        }

        public virtual IEnumerable<MembershipAccountBase> GetAllProfiles()
        {
            var collection = GetDefaultCollection();

            return collection.AsQueryable();
        }

        protected virtual void Save(MembershipAccountBase entity)
        {
            var collection = GetDefaultCollection();

            collection.Save(entity);
        }

        public void CreateProfile(MembershipAccountBase entity)
        {
            int userId = 0;
            var session = new MongoSession(_connectionString);
            userId = session.GetNextSequence("user_id");

            entity.UserId = userId;
            Save(entity);
        }

        public void UpdateProfile(MembershipAccountBase entity)
        {
            Save(entity);
        }

        private void Save(IEnumerable<MembershipAccountBase> entities)
        {
            foreach (var entity in entities)
            {
                Save(entity);
            }
        }

        public void Delete(IEnumerable<MembershipAccountBase> entities)
        {
            foreach (MembershipAccountBase e in entities)
            {
                DeleteProfile(e);
            }
        }

        public void DeleteProfile(MembershipAccountBase entity)
        {
            var collection = GetDefaultCollection();
            var query = Query.EQ("_id", entity.UserId);
            collection.Remove(query);
        }

        #endregion

        #region Helper Methods


        protected virtual MongoCollection<MembershipAccountBase> GetDefaultCollection()
        {
            var collectionName = GetCollectionName();
            var collection = _database.GetCollection<MembershipAccountBase>(collectionName);
            return collection;
        }

        #endregion


        public MembershipAccountBase GetProfileByUserName(string userName)
        {
            return GetDefaultCollection().AsQueryable().FirstOrDefault(x => x.UserName == userName);
        }
    }
}
