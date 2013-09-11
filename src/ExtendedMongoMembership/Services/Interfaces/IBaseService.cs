using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExtendedMongoMembership.Services.Interfaces
{
    public interface IBaseService<TDomian>
        where TDomian : class
    {
        TDomian GetById(dynamic id);
        TDomian GetByName(string name);
        IEnumerable<TDomian> GetAll();
        void Save(TDomian entity);
        void Save(IEnumerable<TDomian> entities);
        void Delete(IEnumerable<TDomian> entities);
        void Delete(TDomian entity);

    }
}
