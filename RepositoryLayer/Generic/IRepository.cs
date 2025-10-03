using System.Linq.Expressions;

namespace RepositoryLayer.Generic
{
    public interface IRepository<T> where T : class
    {
        Task<T?> GetAsync(Expression<Func<T, bool>> expression);
        Task AddAsync(T entity);
    }
}