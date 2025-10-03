
using DataLayer.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.CognitiveServices.Speech;
using Microsoft.CognitiveServices.Speech.Audio; 
using Microsoft.CognitiveServices.Speech.PronunciationAssessment;
using Microsoft.Extensions.Options;
using ServiceLayer.Configs;
using System;
using System.Threading.Tasks;

namespace ServiceLayer.Speech
{
    public class AzureSpeechService : IAzureSpeechService
    {
        private readonly SpeechConfig _speechConfig;

        public AzureSpeechService(IOptions<AzureSpeechSettings> config)
        {
            _speechConfig = SpeechConfig.FromSubscription(config.Value.SubscriptionKey, config.Value.Region);
            _speechConfig.SpeechRecognitionLanguage = "en-US";
        }

        public async Task<SpeechAnalysisDTO> AnalyzePronunciationAsync(IFormFile audioFile, string referenceText)
        {
            // LỖI 2: SỬA LẠI CÁCH TẠO VÀ GHI VÀO STREAM
            // 1. Tạo một PushAudioInputStream
            using var audioInputStream = AudioInputStream.CreatePushStream();
            using var audioConfig = AudioConfig.FromStreamInput(audioInputStream);
            using var recognizer = new SpeechRecognizer(_speechConfig, audioConfig);

            // 2. Đọc file từ IFormFile và ghi vào PushAudioInputStream bằng phương thức Write()
            byte[] buffer = new byte[1024];
            int bytesRead;
            using (var stream = audioFile.OpenReadStream())
            {
                while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    audioInputStream.Write(buffer, bytesRead);
                }
            }
            // 3. Báo cho SDK biết là đã hết dữ liệu
            audioInputStream.Close();

            // Cấu hình Pronunciation Assessment (giữ nguyên)
            var pronunciationConfig = new PronunciationAssessmentConfig(
                referenceText,
                GradingSystem.HundredMark,
                Granularity.Phoneme,
                true);
            pronunciationConfig.ApplyTo(recognizer);

            var result = await recognizer.RecognizeOnceAsync();

            if (result.Reason == ResultReason.RecognizedSpeech)
            {
                var pronunciationResult = PronunciationAssessmentResult.FromResult(result);
                return new SpeechAnalysisDTO
                {
                    Transcript = result.Text,
                    AccuracyScore = pronunciationResult.AccuracyScore,
                    FluencyScore = pronunciationResult.FluencyScore,
                    CompletenessScore = pronunciationResult.CompletenessScore,
                    PronunciationScore = pronunciationResult.PronunciationScore
                };
            }
            else
            {
                // Thêm thông tin chi tiết về lỗi nếu có
                var cancellationDetails = CancellationDetails.FromResult(result);
                string errorMessage = $"Reason: {result.Reason}. Details: {cancellationDetails.ErrorDetails}";
                return new SpeechAnalysisDTO { ErrorMessage = errorMessage };
            }
        }
    }
}