// File: ServiceLayer/Speech/IAzureSpeechService.cs
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
// Tạo một DTO để chứa kết quả trả về
using DataLayer.DTOs;

namespace ServiceLayer.Speech
{
    public interface IAzureSpeechService
    {
        Task<SpeechAnalysisDTO> AnalyzePronunciationAsync(IFormFile audioFile, string referenceText);
    }
}