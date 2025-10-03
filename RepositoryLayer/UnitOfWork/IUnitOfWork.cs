using Microsoft.EntityFrameworkCore.Storage;
using RepositoryLayer.Questions;
using RepositoryLayer.Speaking;


namespace RepositoryLayer.UnitOfWork;

public interface IUnitOfWork : IDisposable
{
    IArticleRepository Articles { get; }
    ICategoryRepository Categories { get; }
    IUserRepository Users { get; }
    IVocabularyRepository Vocabularies { get; }
    IQuestionRepository Questions { get; }
    ISpeakingResultRepository SpeakingResults { get; }
    Task<int> CompleteAsync();
    Task<IDbContextTransaction> BeginTransactionAsync();
}