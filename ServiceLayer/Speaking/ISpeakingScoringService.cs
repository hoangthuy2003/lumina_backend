// File: ServiceLayer/Speaking/ISpeakingScoringService.cs
using DataLayer.DTOs;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace ServiceLayer.Speaking
{
    public interface ISpeakingScoringService
    {
        Task<SpeakingScoringResultDTO> ProcessAndScoreAnswerAsync(IFormFile audioFile, int questionId, int userId, int attemptId);
    }
}