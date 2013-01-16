using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;

namespace ExtendedMongoMembership
{
    public class MembershipAccount //: IUserEntity
    {
        public MembershipAccount()
        {
            Roles = new List<MembershipRole>();
        }

        [BsonId]
        public int UserId { get; set; }
        public DateTime? CreateDate { get; set; }
        public string ConfirmationToken { get; set; }
        public bool IsConfirmed { get; set; }
        public DateTime? LastPasswordFailureDate { get; set; }
        public int PasswordFailuresSinceLastSuccess { get; set; }
        public string Password { get; set; }
        public DateTime? PasswordChangedDate { get; set; }
        public string PasswordSalt { get; set; }
        public string PasswordVerificationToken { get; set; }
        public DateTime? PasswordVerificationTokenExpirationDate { get; set; }

        ////public string OriginalUserName { get; set; }
        //public string UserName { get; set; }
        //public string LoweredUserName { get; set; }
        //public bool IsAnonymous { get; set; }
        //public DateTime LastActivityDate { get; set; }

        //public string Email { get; set; }
        //public string LoweredEmail { get; set; }

        //public string Password { get; set; }
        //public string EncodedPassword { get; set; }
        //public int PasswordFormat { get; set; }
        //public string PasswordFormatString { get; set; }
        //public string PasswordSalt { get; set; }
        //public string PasswordQuestion { get; set; }
        //public string PasswordAnswer { get; set; }

        //public bool IsConfirmed { get; set; }
        //public bool IsLockedOut { get; set; }


        //public DateTime CreateDate { get; set; }
        //public DateTime ModifiedDate { get; set; }
        //public DateTime LastLoginDate { get; set; }
        //public DateTime PasswordChangedDate { get; set; }
        //public DateTime LastLockoutDate { get; set; }

        //public int FailedPasswordAttemptCount { get; set; }
        //public DateTime FailedPasswordAttemptWindowStart { get; set; }
        //public int FailedPasswordAnswerAttemptCount { get; set; }
        //public DateTime FailedPasswordAnswerAttemptWindowStart { get; set; }

        //public string PasswordVerificationToken { get; set; }
        //public DateTime PasswordVerificationTokenExpirationDate { get; set; }

        public List<MembershipRole> Roles { get; set; }

        public string UserName { get; set; }

        public List<OAuthAccountDataEmbedded> OAuthData { get; set; }
    }
}
