// File: lumina/Controllers/SpeakingController.cs
using DataLayer.DTOs;
using lumina.DataLayer.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServiceLayer.Speaking;
using System.Threading.Tasks;

namespace lumina.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class SpeakingController : ControllerBase
    {
        private readonly ISpeakingScoringService _speakingScoringService;

        public SpeakingController(ISpeakingScoringService speakingScoringService)
        {
            _speakingScoringService = speakingScoringService;
        }

        [HttpPost("submit-answer")]
        [Consumes("multipart/form-data")]
        public async Task<IActionResult> SubmitSpeakingAnswer([FromForm] SubmitSpeakingAnswerRequest request)
        {
            if (request?.Audio == null || request.Audio.Length == 0)
            {
                return BadRequest("Audio file is required.");
            }

            try
            {
                var userId = 1;
                var attemptId = 1;

                var result = await _speakingScoringService.ProcessAndScoreAnswerAsync(
                    request.Audio, request.QuestionId, userId, attemptId);

                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }
}