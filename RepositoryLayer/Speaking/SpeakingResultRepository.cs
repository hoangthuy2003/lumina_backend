using DataLayer.Models;
using Microsoft.EntityFrameworkCore;
using RepositoryLayer.Generic;
using System.Linq.Expressions;

namespace RepositoryLayer.Speaking
{
    public class SpeakingResultRepository : ISpeakingResultRepository
    {
        private readonly LuminaSystemContext _context;
        public SpeakingResultRepository(LuminaSystemContext context)
        {
            _context = context;
        }

        public async Task AddAsync(SpeakingResult entity)
        {
            await _context.SpeakingResults.AddAsync(entity);
        }

        public async Task<SpeakingResult?> GetAsync(Expression<Func<SpeakingResult, bool>> expression)
        {
            return await _context.SpeakingResults.FirstOrDefaultAsync(expression);
        }
    }
}