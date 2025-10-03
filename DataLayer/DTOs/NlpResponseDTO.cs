// File: DataLayer/DTOs/Nlp/NlpResponseDTO.cs
namespace DataLayer.DTOs
{
    public class NlpResponseDTO
    {
        public float Grammar_score { get; set; }
        public float Content_score { get; set; }
        public float Vocabulary_score { get; set; }
    }
}