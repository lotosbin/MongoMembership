using ExtendedMongoMembership.Helpers;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Helpers;
using System.Web.Security;
using WebMatrix.WebData;
using WebMatrix.WebData.Resources;

namespace ExtendedMongoMembership
{
    public class MongoMembershipProvider : ExtendedMembershipProvider
    {
        private const int TokenSizeInBytes = 16;
        private readonly MembershipProvider _previousProvider;
        private MongoSession _session;

        static MongoMembershipProvider()
        {
        }

        public MongoMembershipProvider()
            : this(null)
        {
        }

        public MongoMembershipProvider(MembershipProvider previousProvider)
        {
            InitializeCalled = true;
            _previousProvider = previousProvider;
            if (_previousProvider != null)
            {
                _previousProvider.ValidatingPassword += (sender, args) =>
                {
                    if (!InitializeCalled)
                    {
                        OnValidatingPassword(args);
                    }
                };
            }
        }

        private MembershipProvider PreviousProvider
        {
            get
            {
                if (_previousProvider == null)
                {
                    throw new InvalidOperationException("You must call the \"WebSecurity.InitializeDatabaseConnection\" method before you call any other method of the \"WebSecurity\" class. This call should be placed in an _AppStart.cshtml file in the root of your site.");
                }
                else
                {
                    return _previousProvider;
                }
            }
        }

        // Public properties
        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool EnablePasswordRetrieval
        {
            get { return InitializeCalled ? false : PreviousProvider.EnablePasswordRetrieval; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool EnablePasswordReset
        {
            get { return InitializeCalled ? false : PreviousProvider.EnablePasswordReset; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool RequiresQuestionAndAnswer
        {
            get { return InitializeCalled ? false : PreviousProvider.RequiresQuestionAndAnswer; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool RequiresUniqueEmail
        {
            get { return InitializeCalled ? false : PreviousProvider.RequiresUniqueEmail; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipPasswordFormat PasswordFormat
        {
            get { return InitializeCalled ? MembershipPasswordFormat.Hashed : PreviousProvider.PasswordFormat; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MaxInvalidPasswordAttempts
        {
            get { return InitializeCalled ? Int32.MaxValue : PreviousProvider.MaxInvalidPasswordAttempts; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int PasswordAttemptWindow
        {
            get { return InitializeCalled ? Int32.MaxValue : PreviousProvider.PasswordAttemptWindow; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MinRequiredPasswordLength
        {
            get { return InitializeCalled ? 0 : PreviousProvider.MinRequiredPasswordLength; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return InitializeCalled ? 0 : PreviousProvider.MinRequiredNonAlphanumericCharacters; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string PasswordStrengthRegularExpression
        {
            get { return InitializeCalled ? String.Empty : PreviousProvider.PasswordStrengthRegularExpression; }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string ApplicationName
        {
            get
            {
                if (InitializeCalled)
                {
                    throw new NotSupportedException();
                }
                else
                {
                    return PreviousProvider.ApplicationName;
                }
            }
            set
            {
                if (InitializeCalled)
                {
                    throw new NotSupportedException();
                }
                else
                {
                    PreviousProvider.ApplicationName = value;
                }
            }
        }

        internal static string ConnectionString;
        private bool _useAppHarbor;

        internal bool InitializeCalled { get; set; }


        internal void VerifyInitialized()
        {
            if (!InitializeCalled)
            {
                throw new InvalidOperationException("You must call the \"WebSecurity.InitializeDatabaseConnection\" method before you call any other method of the \"WebSecurity\" class. This call should be placed in an _AppStart.cshtml file in the root of your site.");
            }
        }

        // Inherited from ProviderBase - The "previous provider" we get has already been initialized by the Config system,
        // so we shouldn't forward this call
        public override void Initialize(string name, NameValueCollection config)
        {
            InitializeCalled = true;
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }
            if (String.IsNullOrEmpty(name))
            {
                name = "MongoExtendedMembershipProvider";
            }
            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Simple Membership Provider");
            }
            base.Initialize(name, config);


            bool.TryParse(config["useAppHarbor"], out _useAppHarbor);
            if (_useAppHarbor)
            {
                ConnectionString =
                    ConfigurationManager.AppSettings.Get("MONGOHQ_URL") ??
                    ConfigurationManager.AppSettings.Get("MONGOLAB_URI");
            }

            string temp = string.Empty;
            if (string.IsNullOrEmpty(ConnectionString))
            {
                temp = config["connectionStringName"];
                if (string.IsNullOrEmpty(temp))
                    throw new ProviderException(StringResources.GetString(StringResources.Connection_name_not_specified));
                ConnectionString = SecUtility.GetConnectionString(temp, true, true);

                if (string.IsNullOrEmpty(ConnectionString))
                {
                    throw new ProviderException(StringResources.GetString(StringResources.Connection_string_not_found, temp));
                }
            }


            _session = new MongoSession(ConnectionString);

            config.Remove("useAppHarbor");
            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("description");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");

            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                {
                    throw new ProviderException(String.Format("Provider unrecognized attribute: \"{0}\".", attribUnrecognized));
                }
            }
        }

        // Not an override ==> Simple Membership MUST be enabled to use this method
        public int GetUserId(string userName)
        {
            VerifyInitialized();
            return GetUserId(_session, userName);
        }

        private MembershipAccount GetUser(string userName)
        {
            VerifyInitialized();
            var user = _session.Users.FirstOrDefault(x => x.UserName == userName);
            if (user == null)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
            }

            return user;
        }

        internal static int GetUserId(MongoSession session, string userName)
        {

            var result = session.Users.FirstOrDefault(x => x.UserName == userName);
            if (result == null)
                return -1;

            return result.UserId;
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override int GetUserIdFromPasswordResetToken(string token)
        {
            VerifyInitialized();
            var result = _session.Users.FirstOrDefault(x => x.PasswordVerificationToken == token);
            if (result != null)
            {
                return (int)result.UserId;
            }
            return -1;

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.ChangePasswordQuestionAndAnswer(username, password, newPasswordQuestion, newPasswordAnswer);
            }
            throw new NotSupportedException();
        }

        /// <summary>
        /// Sets the confirmed flag for the username if it is correct.
        /// </summary>
        /// <returns>True if the account could be successfully confirmed. False if the username was not found or the confirmation token is invalid.</returns>
        /// <remarks>Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method</remarks>
        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            VerifyInitialized();
            // We need to compare the token using a case insensitive comparison however it seems tricky to do this uniformly across databases when representing the token as a string. 
            // Therefore verify the case on the client
            //session.ConfirmAccount(userTableName, userNameColumn, userIdColumn);
            var row = _session.Users.FirstOrDefault(x => x.ConfirmationToken == accountConfirmationToken && x.UserName == userName);

            if (row == null)
            {
                return false;
            }
            string expectedToken = row.ConfirmationToken;

            if (String.Equals(accountConfirmationToken, expectedToken, StringComparison.Ordinal))
            {
                try
                {
                    row.IsConfirmed = true;
                    _session.Update(row);
                }
                catch (Exception)
                {
                    return false;
                }
            }
            return false;

        }

        /// <summary>
        /// Sets the confirmed flag for the username if it is correct.
        /// </summary>
        /// <returns>True if the account could be successfully confirmed. False if the username was not found or the confirmation token is invalid.</returns>
        /// <remarks>Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method.
        /// There is a tiny possibility where this method fails to work correctly. Two or more users could be assigned the same token but specified using different cases.
        /// A workaround for this would be to use the overload that accepts both the user name and confirmation token.
        /// </remarks>
        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            VerifyInitialized();
            // We need to compare the token using a case insensitive comparison however it seems tricky to do this uniformly across databases when representing the token as a string. 
            // Therefore verify the case on the client
            var rows = _session.Users
                .Where(x => x.ConfirmationToken == accountConfirmationToken)
                .ToList()
                .Where(r => ((string)r.ConfirmationToken).Equals(accountConfirmationToken, StringComparison.Ordinal))
                .ToList();
            Debug.Assert(rows.Count < 2, "By virtue of the fact that the ConfirmationToken is random and unique, we can never have two tokens that are identical.");
            if (!rows.Any())
            {
                return false;
            }
            var row = rows.First();
            row.IsConfirmed = true;
            try
            {
                _session.Update(row);
                return true;
            }
            catch (Exception)
            {
                return false;
            }

        }


        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            VerifyInitialized();

            if (string.IsNullOrEmpty(password))
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            string hashedPassword = Crypto.HashPassword(password);
            if (hashedPassword.Length > 128)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }

            if (string.IsNullOrEmpty(userName))
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
            }

            // Step 1: Check if the user exists in the Users table
            var usr = GetUser(userName);
            if (usr == null)
            {
                // User not found
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }

            // Step 2: Check if the user exists in the Membership table: Error if yes.
            var result = _session.Users.Count(x => x.UserName == userName);
            if (result > 1)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }


            // Step 3: Create user in Membership table
            string token = null;
            object dbtoken = DBNull.Value;
            if (requireConfirmationToken)
            {
                token = GenerateToken();
                dbtoken = token;
            }
            int defaultNumPasswordFailures = 0;

            try
            {
                var now = DateTime.UtcNow;

                usr.Password = hashedPassword;
                usr.PasswordSalt = string.Empty;
                usr.IsConfirmed = !requireConfirmationToken;
                usr.ConfirmationToken = dbtoken as string;
                usr.CreateDate = now;
                usr.PasswordChangedDate = now;
                usr.PasswordFailuresSinceLastSuccess = defaultNumPasswordFailures;

                _session.Update(usr);

                return token;
            }
            catch (Exception)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.CreateUser(username, password, email, passwordQuestion, passwordAnswer, isApproved, providerUserKey, out status);
            }
            throw new NotSupportedException();
        }

        private void CreateUserRow(MongoSession session, string userName, IDictionary<string, object> values)
        {
            // Make sure user doesn't exist
            int userId = GetUserId(session, userName);
            if (userId != -1)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }

            bool result = session.CreateUserRow(userName, values);

            if (!result)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            VerifyInitialized();

            CreateUserRow(_session, userName, values);
            return CreateAccount(userName, password, requireConfirmation);

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string GetPassword(string username, string answer)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetPassword(username, answer);
            }
            throw new NotSupportedException();
        }

        private static bool SetPassword(MongoSession session, MembershipAccount user, string newPassword)
        {
            string hashedPassword = Crypto.HashPassword(newPassword);
            if (hashedPassword.Length > 128)
            {
                throw new ArgumentException("The membership password is too long. (Maximum length is 128 characters).");
            }

            try
            {
                user.Password = hashedPassword;
                user.PasswordSalt = string.Empty;
                user.PasswordChangedDate = DateTime.UtcNow;
                session.Update(user);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.ChangePassword(username, oldPassword, newPassword);
            }

            // REVIEW: are commas special in the password?
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "username");
            }
            if (string.IsNullOrEmpty(oldPassword))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "oldPassword");
            }
            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "newPassword");
            }
            MembershipAccount user;
            try
            {
                user = GetUser(username);
            }
            catch
            {
                return false;
            }
            // First check that the old credentials match
            if (!CheckPassword(_session, user.UserId, oldPassword))
            {
                return false;
            }

            return SetPassword(_session, user, newPassword);

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string ResetPassword(string username, string answer)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.ResetPassword(username, answer);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetUser(providerUserKey, userIsOnline);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetUser(username, userIsOnline);
            }

            MembershipAccount user;
            try
            {
                user = GetUser(username);
            }
            catch (Exception ex)
            {
                return null;
            }

            return new MembershipUser(Membership.Provider.Name, username, user.UserId, null, null, null, true, false, DateTime.MinValue, user.LastLoginDate ?? DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override string GetUserNameByEmail(string email)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetUserNameByEmail(email);
            }
            throw new NotSupportedException();
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool DeleteAccount(string userName)
        {
            VerifyInitialized();

            int userId = GetUserId(_session, userName);
            if (userId == -1)
            {
                return false; // User not found
            }


            try
            {
                _session.DeleteById<MembershipAccount>(userId);
                return true;
            }
            catch (Exception)
            {
                return false;
            }

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.DeleteUser(username, deleteAllRelatedData);
            }

            MembershipAccount user;
            try
            {
                user = GetUser(username);
            }
            catch (Exception)
            {
                return false;
            }
            user.CatchAll = null;
            bool returnValue = false;
            try
            {
                _session.Save(user);
                returnValue = true;
            }
            catch (Exception)
            {
            }

            //if (deleteAllRelatedData) {
            // REVIEW: do we really want to delete from the user table?
            //}
            return returnValue;

        }

        internal bool DeleteUserAndAccountInternal(string userName)
        {
            return DeleteAccount(userName);
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetAllUsers(pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override int GetNumberOfUsersOnline()
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.GetNumberOfUsersOnline();
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.FindUsersByName(usernameToMatch, pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.FindUsersByEmail(emailToMatch, pageIndex, pageSize, out totalRecords);
            }
            throw new NotSupportedException();
        }

        private static int GetPasswordFailuresSinceLastSuccess(MongoSession session, int userId)
        {
            var failure = session.Users.FirstOrDefault(x => x.UserId == userId);
            if (failure != null)
            {
                return failure.PasswordFailuresSinceLastSuccess;
            }
            return -1;
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            int userId = GetUserId(_session, userName);
            if (userId == -1)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No user found was found that has the name \"{0}\".", userName));
            }

            return GetPasswordFailuresSinceLastSuccess(_session, userId);

        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetCreateDate(string userName)
        {
            var user = _session.Users.FirstOrDefault(x => x.UserName == userName);
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No user found was found that has the name \"{0}\".", userName));
            }

            if (user.CreateDate.HasValue)
            {
                return user.CreateDate.Value;
            }
            return DateTime.MinValue;

        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetPasswordChangedDate(string userName)
        {
            var user = _session.Users.FirstOrDefault(x => x.UserName == userName);
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No user found was found that has the name \"{0}\".", userName));
            }

            if (user.PasswordChangedDate.HasValue)
            {
                return user.PasswordChangedDate.Value;
            }
            return DateTime.MinValue;

        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            var user = _session.Users.FirstOrDefault(x => x.UserName == userName);
            if (user == null)
            {
                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No user found was found that has the name \"{0}\".", userName));
            }

            if (user.LastPasswordFailureDate.HasValue)
            {
                return user.LastPasswordFailureDate.Value;
            }
            return DateTime.MinValue;

        }

        private bool CheckPassword(MongoSession session, int userId, string password)
        {
            string hashedPassword = GetHashedPassword(session, userId);
            var user = session.Users.FirstOrDefault(x => x.UserId == userId);
            bool verificationSucceeded = (hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, password));
            if (verificationSucceeded)
            {
                // Reset password failure count on successful credential check
                user.PasswordFailuresSinceLastSuccess = 0;
            }
            else
            {
                int failures = GetPasswordFailuresSinceLastSuccess(session, userId);
                if (failures != -1)
                {
                    user.PasswordFailuresSinceLastSuccess = failures + 1;
                    user.LastPasswordFailureDate = DateTime.UtcNow;
                }
            }

            session.Save(user);
            return verificationSucceeded;
        }

        private string GetHashedPassword(MongoSession session, int userId)
        {
            var user = session.Users.FirstOrDefault(x => x.UserId == userId);
            // REVIEW: Should get exactly one match, should we throw if we get > 1?
            if (user == null)
            {
                return null;
            }
            return user.Password;
        }

        // Ensures the user exists in the accounts table
        private MembershipAccount VerifyUserNameHasConfirmedAccount(MongoSession session, string userName, bool throwException)
        {
            var user = session.Users.FirstOrDefault(x => x.UserName == userName);
            if (user == null)
            {
                if (throwException)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No user found was found that has the name \"{0}\".", userName));
                }
                else
                {
                    return null;
                }
            }

            if (!user.IsConfirmed)
            {
                if (throwException)
                {
                    throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "No account exists for \"{0}\".", userName));
                }
                else
                {
                    return null;
                }
            }
            return user;
        }

        private static string GenerateToken()
        {
            using (var prng = new RNGCryptoServiceProvider())
            {
                return GenerateToken(prng);
            }
        }

        internal static string GenerateToken(RandomNumberGenerator generator)
        {
            byte[] tokenBytes = new byte[TokenSizeInBytes];
            generator.GetBytes(tokenBytes);
            return HttpServerUtility.UrlTokenEncode(tokenBytes);
        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            VerifyInitialized();
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "userName");
            }
            var user = VerifyUserNameHasConfirmedAccount(_session, userName, throwException: true);

            if (user == null)
            {
                throw new InvalidOperationException(String.Format("No user found was found that has the name \"{0}\".", userName));
            }


            if (user.PasswordVerificationToken == null || (user.PasswordVerificationToken != null && user.PasswordVerificationTokenExpirationDate > DateTime.UtcNow))
            {
                user.PasswordVerificationToken = GenerateToken();

            }

            try
            {
                user.PasswordVerificationTokenExpirationDate = DateTime.UtcNow.AddMinutes(tokenExpirationInMinutesFromNow);
                _session.Save(user);
            }
            catch (Exception)
            {
                throw new ProviderException("Database operation failed.");
            }

            return user.PasswordVerificationToken;

        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool IsConfirmed(string userName)
        {
            VerifyInitialized();
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "userName");
            }

            var user = VerifyUserNameHasConfirmedAccount(_session, userName, throwException: false);
            return (user != null);

        }

        // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            VerifyInitialized();
            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "newPassword");
            }
            var user = _session.Users.FirstOrDefault(x => x.PasswordVerificationToken == token && x.PasswordVerificationTokenExpirationDate > DateTime.UtcNow);
            if (user != null)
            {
                bool success = SetPassword(_session, user, newPassword);
                if (success)
                {
                    // Clear the Token on success
                    user.PasswordVerificationToken = null;
                    user.PasswordVerificationTokenExpirationDate = null;
                    try
                    {
                        _session.Update(user);
                    }
                    catch (Exception)
                    {
                        throw new ProviderException("Database operation failed.");
                    }
                }
                return success;
            }
            else
            {
                return false;
            }

        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override void UpdateUser(MembershipUser user)
        {
            if (!InitializeCalled)
            {
                PreviousProvider.UpdateUser(user);
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool UnlockUser(string userName)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.UnlockUser(userName);
            }
            throw new NotSupportedException();
        }

        //internal void ValidateUserTable()
        //{
        //    using (var session = new MongoSession(_connectionString))
        //    {
        //        // GetUser will fail with an exception if the user table isn't set up properly
        //        try
        //        {
        //            GetUserId(db, SafeUserTableName, SafeUserNameColumn, SafeUserIdColumn, "z");
        //        }
        //        catch (Exception e)
        //        {
        //            throw new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, WebDataResources.Security_FailedToFindUserTable, UserTableName), e);
        //        }
        //    }
        //}

        // Inherited from MembershipProvider ==> Forwarded to previous provider if this provider hasn't been initialized
        public override bool ValidateUser(string username, string password)
        {
            if (!InitializeCalled)
            {
                return PreviousProvider.ValidateUser(username, password);
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "username");
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "password");
            }
            var user = VerifyUserNameHasConfirmedAccount(_session, username, throwException: false);
            if (user == null)
            {
                return false;
            }
            else
            {
                var result = CheckPassword(_session, user.UserId, password);
                try
                {
                    if (result)
                    {
                        user.LastLoginDate = DateTime.Now;
                    }
                    else
                    {
                        user.LastPasswordFailureDate = DateTime.Now;
                    }

                    _session.Update(user);
                }
                catch (Exception ex) { }
                return result;
            }

        }

        public override string GetUserNameFromId(int userId)
        {
            VerifyInitialized();

            var user = _session.Users.FirstOrDefault(x => x.UserId == userId);
            if (user == null)
                return null;
            return user.UserName;

        }

        public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
        {
            VerifyInitialized();

            if (string.IsNullOrEmpty(userName))
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }

            var user = GetUser(userName);

            var oldUserId = GetUserIdFromOAuth(provider, providerUserId);
            if (oldUserId == -1)
            {
                // account doesn't exist. create a new one.
                user.OAuthData.Add(new OAuthAccountDataEmbedded(provider, providerUserId));
                try
                {
                    _session.Save(user);
                }
                catch (Exception)
                {
                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                }
            }
            else
            {
                // account already exist. update it
                var oldUser = _session.Users.Where(y => y.OAuthData.Any(x => x.ProviderUserId == providerUserId && x.Provider == provider)).FirstOrDefault();
                var data = oldUser.OAuthData.FirstOrDefault(x => x.ProviderUserId == providerUserId && x.Provider == provider);
                oldUser.OAuthData.Remove(data);
                user.OAuthData.Add(data);
                try
                {
                    _session.Save(oldUser);
                    _session.Save(user);
                }
                catch (Exception)
                {
                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                }
            }

        }

        public override void DeleteOAuthAccount(string provider, string providerUserId)
        {
            VerifyInitialized();

            var user = _session.Users.FirstOrDefault(y => y.OAuthData.Any(x => x.ProviderUserId == providerUserId && x.Provider == provider));
            var data = user.OAuthData.FirstOrDefault(x => x.ProviderUserId == providerUserId && x.Provider == provider);
            user.OAuthData.Remove(data);
            try
            {
                _session.Save(user);
            }
            catch (Exception)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }

        }

        public override int GetUserIdFromOAuth(string provider, string providerUserId)
        {
            VerifyInitialized();

            var user = _session.Users.FirstOrDefault(y => y.OAuthData.Any(x => x.ProviderUserId == providerUserId && x.Provider == provider));
            if (user != null)
            {
                return (int)user.UserId;
            }

            return -1;

        }

        public override string GetOAuthTokenSecret(string token)
        {
            VerifyInitialized();

            // Note that token is case-sensitive
            var oauthToken = _session.OAuthTokens.FirstOrDefault(x => x.Token == token);
            return oauthToken.Secret;

        }

        public override void StoreOAuthRequestToken(string requestToken, string requestTokenSecret)
        {
            VerifyInitialized();

            OAuthToken existingSecret;
            existingSecret = _session.OAuthTokens.FirstOrDefault(x => x.Token == requestToken);

            if (existingSecret != null)
            {
                if (existingSecret.Secret == requestTokenSecret)
                {
                    // the record already exists
                    return;
                }

                // the token exists with old secret, update it to new secret
                existingSecret.Secret = requestTokenSecret;
                _session.Save(existingSecret);

            }
            else
            {
                // insert new record
                OAuthToken newOAuthToken = new OAuthToken
                {
                    Secret = requestTokenSecret,
                    Token = requestToken
                };
                try
                {
                    _session.Save(newOAuthToken);
                }
                catch (Exception)
                {
                    throw new ProviderException("Failed to store OAuth token to database.");
                }

            }
        }

        /// <summary>
        /// Replaces the request token with access token and secret.
        /// </summary>
        /// <param name="requestToken">The request token.</param>
        /// <param name="accessToken">The access token.</param>
        /// <param name="accessTokenSecret">The access token secret.</param>
        public override void ReplaceOAuthRequestTokenWithAccessToken(string requestToken, string accessToken, string accessTokenSecret)
        {
            VerifyInitialized();

            // insert new record
            _session.DeleteById<OAuthToken>(requestToken);

            // Although there are two different types of tokens, request token and access token,
            // we treat them the same in database records.
            StoreOAuthRequestToken(accessToken, accessTokenSecret);

        }

        /// <summary>
        /// Deletes the OAuth token from the backing store from the database.
        /// </summary>
        /// <param name="token">The token to be deleted.</param>
        public override void DeleteOAuthToken(string token)
        {
            VerifyInitialized();

            // Note that token is case-sensitive
            _session.DeleteById<OAuthToken>(token);

        }

        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            VerifyInitialized();

            var user = GetUser(userName);
            if (user != null)
            {
                if (user.OAuthData.Count > 0)
                {
                    var accounts = new List<OAuthAccountData>();
                    foreach (var row in user.OAuthData)
                    {
                        accounts.Add(new OAuthAccountData(row.Provider, row.ProviderUserId));
                    }
                    return accounts;
                }

            }

            return new OAuthAccountData[0];
        }

        /// <summary>
        /// Determines whether there exists a local account (as opposed to OAuth account) with the specified userId.
        /// </summary>
        /// <param name="userId">The user id to check for local account.</param>
        /// <returns>
        ///   <c>true</c> if there is a local account with the specified user id]; otherwise, <c>false</c>.
        /// </returns>
        public override bool HasLocalAccount(int userId)
        {
            VerifyInitialized();

            var user = _session.Users.FirstOrDefault(x => x.UserId == userId);
            return !string.IsNullOrEmpty(user.Password);

        }
    }
}
