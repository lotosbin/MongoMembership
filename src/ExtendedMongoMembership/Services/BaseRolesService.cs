using ExtendedMongoMembership.Services.Interfaces;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using MongoDB.Driver.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Services
{
    public abstract class BaseRolesService : IBaseRolesService
    {
        protected virtual string GetCollectionName()
        {
            return "Roles";
        }

        #region Member Vars

        private readonly string _databaseName;
        private string _connectionString;
        private readonly MongoDatabase _database;
        private MongoServer _server;
        private readonly MongoClient _client;

        #endregion

        #region Constructors

        public BaseRolesService(string connectionString)
        {
            _connectionString = connectionString;
            _databaseName = connectionString.Substring(connectionString.LastIndexOf('/') + 1);
            _client = new MongoClient(connectionString);
            _server = _client.GetServer();
            _database = _server.GetDatabase(_databaseName);
        }

        #endregion

        #region Public Methods

        public virtual MembershipRoleBase GetProfileById(int id)
        {
            var collection = GetDefaultCollection();
            var item = collection.FindOneById(id);

            return item;
        }

        public virtual IEnumerable<MembershipRoleBase> GetRoles()
        {
            var collection = GetDefaultCollection();

            return collection.AsQueryable();
        }

        public virtual void Save(MembershipRoleBase entity)
        {
            var collection = GetDefaultCollection();

            collection.Save(entity);
        }

        public virtual void Save(IEnumerable<MembershipRoleBase> entities)
        {
            foreach (var entity in entities)
            {
                Save(entity);
            }
        }

        public void Delete(IEnumerable<MembershipRoleBase> entities)
        {
            foreach (MembershipRoleBase e in entities)
            {
                Delete(e);
            }
        }

        public void Delete(MembershipRoleBase entity)
        {
            var collection = GetDefaultCollection();
            var query = Query.EQ("_id", entity.RoleId);
            collection.Remove(query);
        }

        #endregion

        #region Helper Methods


        protected virtual MongoCollection<MembershipRoleBase> GetDefaultCollection()
        {
            var collectionName = GetCollectionName();
            var collection = _database.GetCollection<MembershipRoleBase>(collectionName);
            return collection;
        }

        #endregion

        public MembershipRoleBase GetRoleById(Guid id)
        {
            var collection = GetDefaultCollection();

            return collection.AsQueryable().FirstOrDefault(x => x.RoleId == id);
        }

        public MembershipRoleBase GetRoleByRoleName(string roleName)
        {
            var collection = GetDefaultCollection();

            return collection.AsQueryable().FirstOrDefault(x => x.RoleName == roleName);
        }
    }
}
