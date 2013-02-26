﻿using ExtendedMongoMembership.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Services
{
    public interface IUserProfileServiceBase<TEntity>
    {
        TEntity GetProfile(string id);
        TEntity GetProfileByUserName(string userName);
        IEnumerable<TEntity> GetProfiles();
        void CreateProfile(TEntity entity);
        void UpdateProfile(TEntity entity);
        void Delete(IEnumerable<TEntity> entities);
        void DeleteProfile(TEntity entity);
    }
}
