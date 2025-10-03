using DataLayer.Models;
using Microsoft.EntityFrameworkCore;
using RepositoryLayer.Generic;
using System.Linq.Expressions;

namespace RepositoryLayer.Questions
{
    public class QuestionRepository : IQuestionRepository
    {
        private readonly LuminaSystemContext _context;
        public QuestionRepository(LuminaSystemContext context)
        {
            _context = context;
        }

        public async Task AddAsync(Question entity)
        {
            await _context.Questions.AddAsync(entity);
        }

        public async Task<Question?> GetAsync(Expression<Func<Question, bool>> expression)
        {
            return await _context.Questions.FirstOrDefaultAsync(expression);
        }
    }
}