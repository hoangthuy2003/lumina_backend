using System;
using System.Collections.Generic;

namespace DataLayer.Models;

public partial class User
{
    public int UserId { get; set; }

    public string Email { get; set; } = null!;

    public string FullName { get; set; } = null!;

    public int RoleId { get; set; }

    public int? CurrentStreak { get; set; }

    public DateTime? LastPracticeDate { get; set; }

    public string? AvatarUrl { get; set; }

    public string? Bio { get; set; }

    public string? Phone { get; set; }

    public bool? IsActive { get; set; }

    public virtual ICollection<Account> Accounts { get; set; } = new List<Account>();

    public virtual ICollection<ArticleCategory> ArticleCategories { get; set; } = new List<ArticleCategory>();

    public virtual ICollection<Article> ArticleCreatedByNavigations { get; set; } = new List<Article>();

    public virtual ICollection<Article> ArticleUpdatedByNavigations { get; set; } = new List<Article>();

    public virtual ICollection<Event> EventCreateByNavigations { get; set; } = new List<Event>();

    public virtual ICollection<Event> EventUpdateByNavigations { get; set; } = new List<Event>();

    public virtual ICollection<ExamAttempt> ExamAttempts { get; set; } = new List<ExamAttempt>();

    public virtual ICollection<Exam> ExamCreatedByNavigations { get; set; } = new List<Exam>();

    public virtual ICollection<Exam> ExamUpdateByNavigations { get; set; } = new List<Exam>();

    public virtual ICollection<Payment> Payments { get; set; } = new List<Payment>();

    public virtual ICollection<Report> Reports { get; set; } = new List<Report>();

    public virtual Role Role { get; set; } = null!;

    public virtual ICollection<SectionCompletion> SectionCompletions { get; set; } = new List<SectionCompletion>();

    public virtual ICollection<Slide> SlideCreateByNavigations { get; set; } = new List<Slide>();

    public virtual ICollection<Slide> SlideUpdateByNavigations { get; set; } = new List<Slide>();

    public virtual ICollection<Subscription> Subscriptions { get; set; } = new List<Subscription>();

    public virtual ICollection<UserArticleProgress> UserArticleProgresses { get; set; } = new List<UserArticleProgress>();

    public virtual ICollection<UserLeaderboard> UserLeaderboards { get; set; } = new List<UserLeaderboard>();

    public virtual ICollection<UserNote> UserNotes { get; set; } = new List<UserNote>();

    public virtual ICollection<UserNotification> UserNotifications { get; set; } = new List<UserNotification>();

    public virtual ICollection<UserSpacedRepetition> UserSpacedRepetitions { get; set; } = new List<UserSpacedRepetition>();

    public virtual ICollection<VocabularyList> VocabularyLists { get; set; } = new List<VocabularyList>();

    public virtual ICollection<PasswordResetToken> PasswordResetTokens { get; set; } = new List<PasswordResetToken>();
}
