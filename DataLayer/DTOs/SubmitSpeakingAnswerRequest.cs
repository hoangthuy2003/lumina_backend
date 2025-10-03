using Microsoft.AspNetCore.Http;

namespace lumina.DataLayer.DTOs
{
    public class SubmitSpeakingAnswerRequest
    {
        public IFormFile Audio { get; set; }
        public int QuestionId { get; set; }
    }
}