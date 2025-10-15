﻿namespace DataLayer.DTOs.Exam
{
    public class SpeechAnalysisDTO
    {
        public string Transcript { get; set; }
        public double AccuracyScore { get; set; }
        public double FluencyScore { get; set; }
        public double CompletenessScore { get; set; }
        public double PronunciationScore { get; set; }
        public string ErrorMessage { get; set; }
    }
}