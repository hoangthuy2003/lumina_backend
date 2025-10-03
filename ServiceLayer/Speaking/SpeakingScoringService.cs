using DataLayer.DTOs;
using DataLayer.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using RepositoryLayer.UnitOfWork;
using ServiceLayer.Speech;
using ServiceLayer.UploadFile;
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace ServiceLayer.Speaking
{
    public class SpeakingScoringService : ISpeakingScoringService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IUploadService _uploadService;
        private readonly IAzureSpeechService _azureSpeechService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        public SpeakingScoringService(
            IUnitOfWork unitOfWork,
            IUploadService uploadService,
            IAzureSpeechService azureSpeechService,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration)
        {
            _unitOfWork = unitOfWork;
            _uploadService = uploadService;
            _azureSpeechService = azureSpeechService;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        public async Task<SpeakingScoringResultDTO> ProcessAndScoreAnswerAsync(IFormFile audioFile, int questionId, int userId, int attemptId)
        {
            // 1. Tải file âm thanh lên Cloudinary
            var uploadResult = await _uploadService.UploadFileAsync(audioFile);

            // 2. Lấy câu hỏi từ DB để có SampleAnswer (ReferenceText)
            var question = await _unitOfWork.Questions.GetAsync(q => q.QuestionId == questionId);
            if (question == null || string.IsNullOrEmpty(question.SampleAnswer))
            {
                throw new Exception($"Question with ID {questionId} or its sample answer not found.");
            }

            // 3. Gửi file đến Azure để lấy điểm phát âm
            var azureResult = await _azureSpeechService.AnalyzePronunciationAsync(audioFile, question.SampleAnswer);
            if (!string.IsNullOrEmpty(azureResult.ErrorMessage))
            {
                throw new Exception($"Azure analysis failed: {azureResult.ErrorMessage}");
            }

            // 4. Gửi transcript đến Python service để lấy điểm NLP
            var nlpResult = await GetNlpScoresAsync(azureResult.Transcript, question.SampleAnswer);

            // 5. Tính điểm tổng thể (Task 5)
            var overallScore = CalculateOverallScore(question.QuestionType, azureResult, nlpResult);

            // 6. Chuẩn bị và lưu kết quả vào Database
            var userAnswer = new UserAnswer
            {
                AttemptId = attemptId,
                QuestionId = questionId,
                AnswerContent = azureResult.Transcript,
                AudioUrl = uploadResult.Url,
                Score = overallScore // Lưu điểm tổng thể
            };

            var speakingResult = new SpeakingResult
            {
                PronunciationScore = (float?)azureResult.PronunciationScore,
                AccuracyScore = (float?)azureResult.AccuracyScore,
                FluencyScore = (float?)azureResult.FluencyScore,
                CompletenessScore = (float?)azureResult.CompletenessScore,
                GrammarScore = (float?)nlpResult.Grammar_score,
                VocabularyScore = (float?)nlpResult.Vocabulary_score,
                ContentScore = (float?)nlpResult.Content_score,
                UserAnswer = userAnswer
            };

            await _unitOfWork.SpeakingResults.AddAsync(speakingResult);
            await _unitOfWork.CompleteAsync();

            // 7. Tạo DTO để trả về cho controller
            return new SpeakingScoringResultDTO
            {
                Transcript = azureResult.Transcript,
                SavedAudioUrl = uploadResult.Url,
                OverallScore = overallScore,
                PronunciationScore = azureResult.PronunciationScore,
                AccuracyScore = azureResult.AccuracyScore,
                FluencyScore = azureResult.FluencyScore,
                CompletenessScore = azureResult.CompletenessScore,
                GrammarScore = nlpResult.Grammar_score,
                VocabularyScore = nlpResult.Vocabulary_score,
                ContentScore = nlpResult.Content_score
            };
        }

        private float CalculateOverallScore(string questionType, DataLayer.DTOs.SpeechAnalysisDTO azureResult, NlpResponseDTO nlpResult)
        {
            // Định nghĩa trọng số mặc định
            float pronWeight = 0.25f; // Phát âm
            float accWeight = 0.15f; // Độ chính xác
            float fluWeight = 0.20f; // Độ trôi chảy
            float contWeight = 0.20f; // Nội dung
            float gramWeight = 0.10f; // Ngữ pháp
            float vocabWeight = 0.10f; // Từ vựng

            

            // Tính điểm cuối cùng
            double totalScore =
                (azureResult.PronunciationScore * pronWeight) +
                (azureResult.AccuracyScore * accWeight) +
                (azureResult.FluencyScore * fluWeight) +
                (nlpResult.Content_score * contWeight) +
                (nlpResult.Grammar_score * gramWeight) +
                (nlpResult.Vocabulary_score * vocabWeight);

            double totalWeight = pronWeight + accWeight + fluWeight + contWeight + gramWeight + vocabWeight;
            if (totalWeight > 0)
            {
                totalScore /= totalWeight;
            }

            return (float)Math.Round(totalScore, 2);
        }

        private async Task<NlpResponseDTO> GetNlpScoresAsync(string transcript, string sampleAnswer)
        {
            var client = _httpClientFactory.CreateClient();
            var nlpServiceUrl = _configuration["ServiceUrls:NlpService"];

            if (string.IsNullOrEmpty(nlpServiceUrl))
            {
                throw new Exception("NLP Service URL is not configured in appsettings.json.");
            }

            var request = new NlpRequestDTO
            {
                Transcript = transcript,
                Sample_answer = sampleAnswer
            };

            var response = await client.PostAsJsonAsync($"{nlpServiceUrl}/score_nlp", request);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new Exception($"Failed to get scores from NLP service. Status: {response.StatusCode}, Details: {errorContent}");
            }

            return await response.Content.ReadFromJsonAsync<NlpResponseDTO>();
        }
    }
}