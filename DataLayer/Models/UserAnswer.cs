using System;
using System.Collections.Generic;

namespace DataLayer.Models;

public partial class UserAnswer
{
    public int UserAnswerId { get; set; }

    public int AttemptId { get; set; }

    public int QuestionId { get; set; }

    public int? SelectedOptionId { get; set; }

    public string? AnswerContent { get; set; }

    public float? Score { get; set; }

    public bool? IsCorrect { get; set; }

    public string? FeedbackAi { get; set; }
    public string? AudioUrl { get; set; }
    public virtual ExamAttempt Attempt { get; set; } = null!;

    public virtual Question Question { get; set; } = null!;
    public virtual SpeakingResult? SpeakingResult { get; set; }
    public virtual Option? SelectedOption { get; set; }
}
