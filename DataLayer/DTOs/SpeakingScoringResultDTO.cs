// File: DataLayer/DTOs/Speaking/SpeakingScoringResultDTO.cs
namespace DataLayer.DTOs
{
    public class SpeakingScoringResultDTO
    {
        public string Transcript { get; set; }
        public string SavedAudioUrl { get; set; }
        public double? OverallScore { get; set; } // Sẽ tính ở Task 5

        // Điểm từ Azure
        public double? PronunciationScore { get; set; }
        public double? AccuracyScore { get; set; }
        public double? FluencyScore { get; set; }
        public double? CompletenessScore { get; set; }

        // Điểm từ Python
        public double? GrammarScore { get; set; }
        public double? VocabularyScore { get; set; }
        public double? ContentScore { get; set; }
    }
}