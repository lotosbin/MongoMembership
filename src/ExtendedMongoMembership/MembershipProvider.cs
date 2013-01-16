
namespace ExtendedMongoMembership
{

    //public sealed class SimpleMongoProvider : ExtendedMembershipProvider
    //{
    //    private const int TokenSizeInBytes = 16;
    //    private int _newPasswordLength = 8;
    //    private string _eventSource = "MongoMembershipProvider";
    //    private string _eventLog = "Application";
    //    private string _exceptionMessage = "An exception occurred. Please check the Event Log.";
    //    private string _connectionString;
    //    private int _minRequiredPasswordLength;
    //    private bool _writeExceptionsToEventLog;
    //    private bool _enablePasswordReset;
    //    private bool _enablePasswordRetrieval;
    //    private bool _requiresQuestionAndAnswer;
    //    private bool _requiresUniqueEmail;
    //    private int _maxInvalidPasswordAttempts;
    //    private int _passwordAttemptWindow;
    //    private MembershipPasswordFormat _passwordFormat;

    //    private MembershipPasswordCompatibilityMode _legacyPasswordCompatibilityMode;
    //    private string s_HashAlgorithm;
    //    private const int SALT_SIZE = 16;
    //    private const int PASSWORD_SIZE = 14;

    //    private int _minRequiredNonAlphanumericCharacters;
    //    private string _passwordStrengthRegularExpression;

    //    private string _AppName;
    //    private int? _AppId;
    //    /// <summary>
    //    /// Initializes the MongoDb membership provider with the property values specified in the 
    //    /// ASP.NET application's configuration file. This method is not intended to be used directly 
    //    /// from your code. 
    //    /// </summary>
    //    /// <param name="name">The name of the <see cref="MongoMembershipProvider"/> instance to initialize.</param>
    //    /// <param name="config">A collection of the name/value pairs representing the 
    //    /// provider-specific attributes specified in the configuration for this provider.</param>
    //    /// <exception cref="T:System.ArgumentNullException">config is a null reference.</exception>
    //    /// <exception cref="T:System.InvalidOperationException">An attempt is made to call <see cref="M:System.Configuration.Provider.ProviderBase.Initialize(System.String,System.Collections.Specialized.NameValueCollection)"/> on a provider after the provider has already been initialized.</exception>
    //    /// <exception cref="T:System.Configuration.Provider.ProviderException"></exception>
    //    public override void Initialize(string name, NameValueCollection config)
    //    {
    //        /*DateTimeSerializationOptions.Defaults = new DateTimeSerializationOptions(DateTimeKind.Local, BsonType.Document);*/

    //        if (config == null)
    //        {
    //            throw new ArgumentNullException("config");
    //        }
    //        if (name == null || name.Length == 0)
    //        {
    //            name = "MongoMembershipProvider";
    //        }
    //        if (string.IsNullOrEmpty(config["description"]))
    //        {
    //            config.Remove("description");
    //            config.Add("description", "Mongo default application");
    //        }
    //        base.Initialize(name, config);


    //        _AppName = GetConfigValue(config["applicationName"], HostingEnvironment.ApplicationVirtualPath);

    //        if (string.IsNullOrEmpty(_AppName))
    //            _AppName = SecUtility.GetDefaultAppName();

    //        if (_AppName.Length > 256)
    //        {
    //            throw new ProviderException(StringResources.GetString(StringResources.Provider_application_name_too_long));
    //        }


    //        _maxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));

    //        _passwordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));

    //        _minRequiredNonAlphanumericCharacters =
    //            Convert.ToInt32(GetConfigValue(config["minRequiredNonalphanumericCharacters"], "1"));

    //        _minRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));

    //        _passwordStrengthRegularExpression =
    //            Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], ""));

    //        _enablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "True"));

    //        _enablePasswordRetrieval = Convert.ToBoolean(
    //            GetConfigValue(config["enablePasswordRetrieval"], "False"));

    //        _requiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "False"));

    //        _requiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "True"));

    //        _writeExceptionsToEventLog = Convert.ToBoolean(GetConfigValue(config["writeExceptionsToEventLog"], "True"));

    //        string temp_format = config["passwordFormat"];

    //        if (temp_format == null)
    //            temp_format = "hashed";
    //        else
    //            temp_format = temp_format.ToLowerInvariant();

    //        if (temp_format == "hashed")
    //            _passwordFormat = MembershipPasswordFormat.Hashed;
    //        else if (temp_format == "encrypted")
    //            _passwordFormat = MembershipPasswordFormat.Encrypted;
    //        else if (temp_format == "clear")
    //            _passwordFormat = MembershipPasswordFormat.Clear;
    //        else
    //            throw new ProviderException("Password format not supported.");

    //        // if the user is asking for the ability to retrieve hashed passwords, then let
    //        // them know we can't
    //        if (_passwordFormat == MembershipPasswordFormat.Hashed)
    //        {
    //            if (EnablePasswordRetrieval)
    //                throw new ProviderException(StringResources.GetString(StringResources.Provider_can_not_retrieve_hashed_password));
    //        }

    //        string value = config["passwordCompatMode"];
    //        if (!string.IsNullOrEmpty(value))
    //        {
    //            this._legacyPasswordCompatibilityMode = (MembershipPasswordCompatibilityMode)Enum.Parse(typeof(MembershipPasswordCompatibilityMode), value);
    //        }



    //        string temp = config["connectionStringName"];

    //        if (string.IsNullOrEmpty(temp))
    //            throw new ProviderException(StringResources.GetString(StringResources.Connection_name_not_specified));

    //        _connectionString = SecUtility.GetConnectionString(temp, true, true);

    //        if (string.IsNullOrEmpty(_connectionString))
    //        {
    //            throw new ProviderException(StringResources.GetString(StringResources.Connection_string_not_found, temp));
    //        }

    //    }

    //    private static string GetConfigValue(string configValue, string defaultValue)
    //    {
    //        if (string.IsNullOrEmpty(configValue))
    //        {
    //            return defaultValue;
    //        }
    //        return configValue;
    //    }

    //    #region Properties

    //    /// <summary>
    //    /// The name of the application using the MongoDb membership provider.
    //    /// </summary>
    //    /// <value>The name of the application using the MongoDb membership provider.  The default is the 
    //    /// application virtual path.</value>
    //    /// <remarks>The ApplicationName is used by the MongoDbMembershipProvider to separate 
    //    /// membership information for multiple applications.  Using different application names, 
    //    /// applications can use the same membership database.
    //    /// Likewise, multiple applications can make use of the same membership data by simply using
    //    /// the same application name.
    //    /// Caution should be taken with multiple applications as the ApplicationName property is not
    //    /// thread safe during writes.
    //    /// </remarks>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// The application name setting is being used.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override string ApplicationName
    //    {
    //        get { return _AppName; }
    //        set { _AppName = value; }
    //    }

    //    /// <summary>
    //    /// Indicates whether the membership provider is configured to allow users to reset their passwords.
    //    /// </summary>
    //    /// <value>true if the membership provider supports password reset; otherwise, false. The default is true.</value>
    //    /// <remarks>Allows the user to replace their password with a new, randomly generated password.  
    //    /// This can be especially handy when using hashed passwords since hashed passwords cannot be
    //    /// retrieved.</remarks>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override bool EnablePasswordReset
    //    {
    //        get { return _enablePasswordReset; }
    //    }

    //    /// <summary>
    //    /// Indicates whether the membership provider is configured to allow users to retrieve 
    //    /// their passwords.
    //    /// </summary>
    //    /// <value>true if the membership provider is configured to support password retrieval; 
    //    /// otherwise, false. The default is false.</value>
    //    /// <remarks>If the system is configured to use hashed passwords, then retrieval is not possible.  
    //    /// If the user attempts to initialize the provider with hashed passwords and enable password retrieval
    //    /// set to true then a <see cref="ProviderException"/> is thrown.</remarks>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override bool EnablePasswordRetrieval
    //    {
    //        get { return _enablePasswordRetrieval; }
    //    }

    //    /// <summary>
    //    /// Gets a value indicating whether the membership provider is 
    //    /// configured to require the user to answer a password question 
    //    /// for password reset and retrieval.
    //    /// </summary>
    //    /// <value>true if a password answer is required for password 
    //    /// reset and retrieval; otherwise, false. The default is false.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override bool RequiresQuestionAndAnswer
    //    {
    //        get { return _requiresQuestionAndAnswer; }
    //    }

    //    /// <summary>
    //    /// Gets a value indicating whether the membership provider is configured 
    //    /// to require a unique e-mail address for each user name.
    //    /// </summary>
    //    /// <value>true if the membership provider requires a unique e-mail address; 
    //    /// otherwise, false. The default is true.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override bool RequiresUniqueEmail
    //    {
    //        get { return _requiresUniqueEmail; }
    //    }

    //    /// <summary>
    //    /// Gets the number of invalid password or password-answer attempts allowed 
    //    /// before the membership user is locked out.
    //    /// </summary>
    //    /// <value>The number of invalid password or password-answer attempts allowed 
    //    /// before the membership user is locked out.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override int MaxInvalidPasswordAttempts
    //    {
    //        get { return _maxInvalidPasswordAttempts; }
    //    }

    //    /// <summary>
    //    /// Gets the number of minutes in which a maximum number of invalid password or 
    //    /// password-answer attempts are allowed before the membership user is locked out.
    //    /// </summary>
    //    /// <value>The number of minutes in which a maximum number of invalid password or 
    //    /// password-answer attempts are allowed before the membership user is locked out.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override int PasswordAttemptWindow
    //    {
    //        get { return _passwordAttemptWindow; }
    //    }

    //    /// <summary>
    //    /// Gets a value indicating the format for storing passwords in the membership data store.
    //    /// </summary>
    //    /// <value>One of the <see cref="T:System.Web.Security.MembershipPasswordFormat"/> 
    //    /// values indicating the format for storing passwords in the data store.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override MembershipPasswordFormat PasswordFormat
    //    {
    //        get { return _passwordFormat; }
    //    }

    //    /// <summary>
    //    /// Gets the minimum number of special characters that must be present in a valid password.
    //    /// </summary>
    //    /// <value>The minimum number of special characters that must be present 
    //    /// in a valid password.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override int MinRequiredNonAlphanumericCharacters
    //    {
    //        get { return _minRequiredNonAlphanumericCharacters; }
    //    }

    //    /// <summary>
    //    /// Gets the minimum length required for a password.
    //    /// </summary>
    //    /// <value>The minimum length required for a password. </value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override int MinRequiredPasswordLength
    //    {
    //        get { return _minRequiredPasswordLength; }
    //    }

    //    /// <summary>
    //    /// Gets the regular expression used to evaluate a password.
    //    /// </summary>
    //    /// <value>A regular expression used to evaluate a password.</value>
    //    /// <example>
    //    /// The following example shows the membership element being used in an applications web.config file.
    //    /// In this example, the regular expression specifies that the password must meet the following
    //    /// criteria:
    //    /// <ul>
    //    /// <list>Is at least seven characters.</list>
    //    /// <list>Contains at least one digit.</list>
    //    /// <list>Contains at least one special (non-alphanumeric) character.</list>
    //    /// </ul>
    //    /// <code source="CodeExamples/MembershipCodeExample1.xml"/>
    //    /// </example>
    //    public override string PasswordStrengthRegularExpression
    //    {
    //        get { return _passwordStrengthRegularExpression; }
    //    }

    //    /// <summary>
    //    /// Gets or sets a value indicating whether exceptions are written to the event log.
    //    /// </summary>
    //    /// <value>
    //    /// 	<c>true</c> if exceptions should be written to the log; otherwise, <c>false</c>.
    //    /// </value>
    //    public bool WriteExceptionsToEventLog
    //    {
    //        get { return _writeExceptionsToEventLog; }
    //        set { _writeExceptionsToEventLog = value; }
    //    }

    //    #endregion

    //    #region Public Methods

    //    /// <summary>
    //    /// Changes the password.
    //    /// </summary>
    //    /// <param name="username">The username.</param>
    //    /// <param name="oldPassword">The old password.</param>
    //    /// <param name="newPassword">The new password.</param>
    //    /// <returns>true if the password was updated successfully, false if the supplied old password
    //    /// is invalid, the user is locked out, or the user does not exist in the database.</returns>
    //    public override bool ChangePassword(string username, string oldPassword, string newPassword)
    //    {

    //        SecUtility.CheckParameter(ref username, true, true, true, 256, "username");
    //        SecUtility.CheckParameter(ref oldPassword, true, true, false, 128, "oldPassword");
    //        SecUtility.CheckParameter(ref newPassword, true, true, false, 128, "newPassword");


    //        // this will return false if the username doesn't exist
    //        if (!(ValidateUser(username, oldPassword)))
    //            return false;

    //        ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, true);
    //        OnValidatingPassword(args);
    //        if (args.Cancel)
    //        {
    //            if (!(args.FailureInformation == null))
    //                throw args.FailureInformation;
    //            else
    //                throw new ProviderException("Change password operation was canceled.");
    //        }

    //        // validate the password according to current guidelines
    //        if (!ValidatePassword(newPassword, "newPassword", true))
    //            return false;

    //        try
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                // retrieve the existing key and format for this user
    //                string passwordKey;
    //                MembershipPasswordFormat passwordFormat;
    //                var user = GetUserByName(username);

    //                GetPasswordInfo(user.UserId, out passwordKey, out passwordFormat);

    //                user.Password = EncodePassword(newPassword, (int)passwordFormat, passwordKey);
    //                user.PasswordChangedDate = DateTime.Now;
    //                session.Update(user);

    //                return true;

    //            }
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "ChangePassword");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Changes the password question and answer.
    //    /// </summary>
    //    /// <param name="username">The username.</param>
    //    /// <param name="password">The password.</param>
    //    /// <param name="newPwdQuestion">The new password question.</param>
    //    /// <param name="newPwdAnswer">The new password answer.</param>
    //    /// <returns>true if the update was successful; otherwise, false. A value of false is 
    //    /// also returned if the password is incorrect, the user is locked out, or the user 
    //    /// does not exist in the database.</returns>
    //    public override bool ChangePasswordQuestionAndAnswer(string username,
    //        string password, string newPwdQuestion, string newPwdAnswer)
    //    {
    //        // this handles the case where the username doesn't exist
    //        if (!(ValidateUser(username, password)))
    //            return false;

    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                // retrieve the existing key and format for this user
    //                string passwordKey;
    //                MembershipPasswordFormat passwordFormat;
    //                var user = GetUserByName(username);

    //                GetPasswordInfo(user.UserId, out passwordKey, out passwordFormat);

    //                user.PasswordQuestion = newPwdQuestion;
    //                user.PasswordAnswer = EncodePassword(newPwdAnswer, (int)passwordFormat, passwordKey);
    //                session.Update(user);

    //                return true;

    //            }

    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "ChangePasswordQuestionAndAnswer");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Adds a new membership user to the data source.
    //    /// </summary>
    //    /// <param name="username">The user name for the new user.</param>
    //    /// <param name="password">The password for the new user.</param>
    //    /// <param name="email">The e-mail address for the new user.</param>
    //    /// <param name="passwordQuestion">The password question for the new user.</param>
    //    /// <param name="passwordAnswer">The password answer for the new user</param>
    //    /// <param name="isApproved">Whether or not the new user is approved to be validated.</param>
    //    /// <param name="providerUserKey">The unique identifier from the membership data source for the user.</param>
    //    /// <param name="status">A <see cref="T:System.Web.Security.MembershipCreateStatus"/> enumeration value indicating whether the user was created successfully.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the information for the newly created user.
    //    /// </returns>
    //    /// 
    //    /// 
    //    /// 

    //    public override MembershipUser CreateUser(string username, string password,
    //               string email, string passwordQuestion, string passwordAnswer,
    //               bool isApproved, object providerUserKey, out MembershipCreateStatus status)
    //    {
    //        ValidatePasswordEventArgs Args = new ValidatePasswordEventArgs(username, password, true);
    //        OnValidatingPassword(Args);
    //        if (Args.Cancel)
    //        {
    //            status = MembershipCreateStatus.InvalidPassword;
    //            return null;
    //        }
    //        if (RequiresUniqueEmail && !String.IsNullOrEmpty(GetUserNameByEmail(email)))
    //        {
    //            status = MembershipCreateStatus.DuplicateEmail;
    //            return null;
    //        }

    //        ValidateQA(passwordQuestion, passwordAnswer);

    //        // now try to validate the password
    //        if (!ValidatePassword(password, "password", false))
    //        {
    //            status = MembershipCreateStatus.InvalidPassword;
    //            return null;
    //        }

    //        // now check to see if we already have a member by this name
    //        MembershipUser u = GetUser(username, false);
    //        if (u != null)
    //        {
    //            status = MembershipCreateStatus.DuplicateUserName;
    //            return null;
    //        }

    //        string passwordKey = GetPasswordKey();
    //        DateTime createDate = DateTime.Now;

    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            try
    //            {


    //                DateTime dt = RoundToSeconds(DateTime.UtcNow);

    //                var user = new MembershipAccount
    //                {
    //                    UserName = username,
    //                    LoweredUserName = username.ToLowerInvariant(),
    //                    Password = EncodePassword(password, (int)PasswordFormat, passwordKey),
    //                    EncodedPassword = EncodePassword(password, (int)PasswordFormat, passwordKey),
    //                    PasswordSalt = passwordKey,
    //                    PasswordAnswer = EncodePassword(passwordAnswer, (int)PasswordFormat, passwordKey),
    //                    PasswordQuestion = passwordQuestion,
    //                    PasswordFormat = (int)PasswordFormat,
    //                    PasswordFormatString = PasswordFormat.ToString(),
    //                    Email = email,
    //                    LoweredEmail = email.ToLowerInvariant(),

    //                    IsConfirmed = isApproved,
    //                    IsLockedOut = false,
    //                    IsAnonymous = false,

    //                    LastActivityDate = dt,
    //                    LastLoginDate = dt,
    //                    LastLockoutDate = dt,
    //                    PasswordChangedDate = dt,

    //                    FailedPasswordAnswerAttemptCount = 0,
    //                    FailedPasswordAttemptCount = 0,
    //                    FailedPasswordAnswerAttemptWindowStart = dt,
    //                    FailedPasswordAttemptWindowStart = dt,

    //                    CreateDate = dt,

    //                };

    //                session.Add(user);

    //                status = MembershipCreateStatus.Success;

    //                providerUserKey = user.UserId;

    //                dt = dt.ToLocalTime();

    //                return new MembershipUser(this.Name,
    //                                           username,
    //                                           providerUserKey,
    //                                           email,
    //                                           passwordQuestion,
    //                                           null,
    //                                           isApproved,
    //                                           false,
    //                                           dt,
    //                                           dt,
    //                                           dt,
    //                                           dt,
    //                                           new DateTime(1754, 1, 1));


    //            }
    //            catch (Exception e)
    //            {
    //                if (WriteExceptionsToEventLog)
    //                    WriteToEventLog(e, "CreateUser");
    //                status = MembershipCreateStatus.ProviderError;

    //                //return null;
    //                throw e;
    //            }
    //        }

    //        //return GetUser(username, false);
    //    }



    //    /// <summary>
    //    /// Removes a user from the membership data source.
    //    /// </summary>
    //    /// <param name="username">The name of the user to delete.</param>
    //    /// <param name="deleteAllRelatedData">true to delete data related to the user from the database; false to leave data related to the user in the database.</param>
    //    /// <returns>
    //    /// true if the user was successfully deleted; otherwise, false.
    //    /// </returns>
    //    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    //    {
    //        try
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var account = (from u in session.Users
    //                               where u.UserName == username
    //                               select u).SingleOrDefault();



    //                // if we are supposed to delete all related data, then delegate that to those providers
    //                //if (deleteAllRelatedData)
    //                //{
    //                //    MongoRoleProvider.DeleteUserData(conn, userId);
    //                //    MongoProfileProvider.DeleteUserData(conn, userId);
    //                //}

    //                if (account != null)
    //                {
    //                    IMongoQuery query = Query.EQ("_id", account.UserId);
    //                    session.Delete<MembershipAccount>(query);
    //                    return true;
    //                }

    //                return false;



    //            }
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "DeleteUser");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Gets a collection of all the users in the data source in pages of data.
    //    /// </summary>
    //    /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param>
    //    /// <param name="pageSize">The size of the page of results to return.</param>
    //    /// <param name="totalRecords">The total number of matched users.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
    //    /// </returns>
    //    public override MembershipUserCollection GetAllUsers(int pageIndex,
    //        int pageSize, out int totalRecords)
    //    {
    //        //return GetUsers(null, null, pageIndex, pageSize, out totalRecords);

    //        if (pageIndex < 0)
    //            throw new ArgumentException(StringResources.GetString(StringResources.PageIndex_bad), "pageIndex");
    //        if (pageSize < 1)
    //            throw new ArgumentException(StringResources.GetString(StringResources.PageSize_bad), "pageSize");

    //        long upperBound = (long)pageIndex * pageSize + pageSize - 1;
    //        if (upperBound > Int32.MaxValue)
    //            throw new ArgumentException(StringResources.GetString(StringResources.PageIndex_PageSize_bad), "pageIndex and pageSize");

    //        MembershipUserCollection users = new MembershipUserCollection();

    //        totalRecords = 0;

    //        try
    //        {


    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var members = session.Users.Skip(pageIndex).Take(pageSize);

    //                totalRecords = session.Users.Count();

    //                foreach (var user in members)
    //                {
    //                    string username, email, passwordQuestion, comment;
    //                    bool isApproved;
    //                    DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
    //                    int? userId;
    //                    bool isLockedOut;
    //                    DateTime dtLastLockoutDate;

    //                    username = user.UserName;
    //                    email = user.Email;
    //                    passwordQuestion = user.PasswordQuestion;
    //                    isApproved = user.IsConfirmed;
    //                    dtCreate = user.CreateDate.ToLocalTime();
    //                    dtLastLogin = user.LastLoginDate.ToLocalTime();
    //                    dtLastActivity = user.LastActivityDate.ToLocalTime();
    //                    dtLastPassChange = user.PasswordChangedDate.ToLocalTime();
    //                    userId = user.UserId;
    //                    isLockedOut = user.IsLockedOut;
    //                    dtLastLockoutDate = user.LastLockoutDate.ToLocalTime();

    //                    users.Add(new MembershipUser(this.Name,
    //                                                   username,
    //                                                   userId,
    //                                                   email,
    //                                                   passwordQuestion,
    //                                                   string.Empty,
    //                                                   isApproved,
    //                                                   isLockedOut,
    //                                                   dtCreate,
    //                                                   dtLastLogin,
    //                                                   dtLastActivity,
    //                                                   dtLastPassChange,
    //                                                   dtLastLockoutDate));
    //                }


    //            }


    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetAllUsers");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }

    //        return users;
    //    }

    //    /// <summary>
    //    /// Gets the number of users currently accessing the application.
    //    /// </summary>
    //    /// <returns>
    //    /// The number of users currently accessing the application.
    //    /// </returns>
    //    public override int GetNumberOfUsersOnline()
    //    {
    //        TimeSpan onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
    //        DateTime compareTime = DateTime.Now.Subtract(onlineSpan);

    //        try
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var users = from u in session.Users
    //                            where u.LastActivityDate > compareTime
    //                            select u;

    //                return users.Count();

    //            }
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetNumberOfUsersOnline");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Gets the password for the specified user name from the data source.
    //    /// </summary>
    //    /// <param name="username">The user to retrieve the password for.</param>
    //    /// <param name="answer">The password answer for the user.</param>
    //    /// <returns>
    //    /// The password for the specified user name.
    //    /// </returns>
    //    public override string GetPassword(string username, string answer)
    //    {
    //        if (!EnablePasswordRetrieval)
    //            throw new ProviderException("Password retrieval not enabled");

    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var account = (from u in session.Users
    //                               where u.UserName == username
    //                               select u).SingleOrDefault();


    //                if (account == null)
    //                {
    //                    throw new ProviderException("Invalid user name or non-existent user account");
    //                }

    //                if (account.IsLockedOut)
    //                    throw new MembershipPasswordException("Account is locked out");

    //                string password = account.Password;
    //                string passwordAnswer = account.PasswordAnswer;
    //                string passwordKey = account.PasswordSalt;
    //                MembershipPasswordFormat format = (MembershipPasswordFormat)account.PasswordFormat;

    //                if (RequiresQuestionAndAnswer &&
    //                    !(CheckPassword(answer, passwordAnswer, passwordKey, format)))
    //                {
    //                    UpdateFailureCount(account.UserId, "PasswordAnswer");
    //                    throw new MembershipPasswordException("Incorrect password answer");
    //                }
    //                if (PasswordFormat == MembershipPasswordFormat.Encrypted)
    //                {
    //                    password = UnEncodePassword(password, format);
    //                }
    //                return password;

    //            }


    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetPassword");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Gets information from the data source for a user. Provides an option to update the last-activity date/time stamp for the user.
    //    /// </summary>
    //    /// <param name="username">The name of the user to get information for.</param>
    //    /// <param name="userIsOnline">true to update the last-activity date/time stamp for the user; false to return user information without updating the last-activity date/time stamp for the user.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the specified user's information from the data source.
    //    /// </returns>
    //    public override MembershipUser GetUser(string username, bool userIsOnline)
    //    {
    //        SecUtility.CheckParameter(
    //                        ref username,
    //                        true,
    //                        false,
    //                        true,
    //                        256,
    //                        "username");


    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var user = (from r in session.Users
    //                            where r.UserName == username
    //                            select r).SingleOrDefault();


    //                if (user == null)
    //                {
    //                    return null;
    //                }


    //                if (userIsOnline)
    //                {
    //                    user.LastActivityDate = DateTime.UtcNow;
    //                    session.Update(user);
    //                }

    //                string email = user.Email;
    //                string passwordQuestion = user.PasswordQuestion;
    //                string comment = string.Empty;
    //                bool isApproved = user.IsConfirmed;
    //                DateTime dtCreate = user.CreateDate.ToLocalTime();
    //                DateTime dtLastLogin = user.LastLoginDate.ToLocalTime();
    //                DateTime dtLastActivity = user.LastActivityDate.ToLocalTime();
    //                DateTime dtLastPassChange = user.PasswordChangedDate.ToLocalTime();
    //                string userName = user.UserName;
    //                bool isLockedOut = user.IsLockedOut;
    //                DateTime dtLastLockoutDate = user.LastLockoutDate.ToLocalTime();

    //                return new MembershipUser(this.Name,
    //                                           userName,
    //                                           user.UserId,
    //                                           email,
    //                                           passwordQuestion,
    //                                           comment,
    //                                           isApproved,
    //                                           isLockedOut,
    //                                           dtCreate,
    //                                           dtLastLogin,
    //                                           dtLastActivity,
    //                                           dtLastPassChange,
    //                                           dtLastLockoutDate);


    //            }

    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetUser(string username, bool userIsOnline)");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Gets user information from the data source based on the unique identifier for the membership user. Provides an option to update the last-activity date/time stamp for the user.
    //    /// </summary>
    //    /// <param name="providerUserKey">The unique identifier for the membership user to get information for.</param>
    //    /// <param name="userIsOnline">true to update the last-activity date/time stamp for the user; false to return user information without updating the last-activity date/time stamp for the user.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the specified user's information from the data source.
    //    /// </returns>
    //    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    //    {
    //        if (providerUserKey == null)
    //        {
    //            throw new ArgumentNullException("providerUserKey");
    //        }

    //        //if (!(providerUserKey is ObjectId))
    //        //{
    //        //    throw new ArgumentException(StringResources.GetString(StringResources.Membership_InvalidProviderUserKey), "providerUserKey");
    //        //}

    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var user = (from r in session.Users
    //                            where r.UserId == int.Parse(providerUserKey.ToString())
    //                            select r).SingleOrDefault();


    //                if (user == null)
    //                {
    //                    return null;
    //                }


    //                if (userIsOnline)
    //                {
    //                    user.LastActivityDate = DateTime.UtcNow;
    //                    session.Update(user);
    //                }

    //                string email = user.Email;
    //                string passwordQuestion = user.PasswordQuestion;
    //                string comment = string.Empty;
    //                bool isApproved = user.IsConfirmed;
    //                DateTime dtCreate = user.CreateDate.ToLocalTime();
    //                DateTime dtLastLogin = user.LastLoginDate.ToLocalTime();
    //                DateTime dtLastActivity = user.LastActivityDate.ToLocalTime();
    //                DateTime dtLastPassChange = user.PasswordChangedDate.ToLocalTime();
    //                string userName = user.UserName;
    //                bool isLockedOut = user.IsLockedOut;
    //                DateTime dtLastLockoutDate = user.LastLockoutDate.ToLocalTime();

    //                return new MembershipUser(this.Name,
    //                                           userName,
    //                                           providerUserKey,
    //                                           email,
    //                                           passwordQuestion,
    //                                           comment,
    //                                           isApproved,
    //                                           isLockedOut,
    //                                           dtCreate,
    //                                           dtLastLogin,
    //                                           dtLastActivity,
    //                                           dtLastPassChange,
    //                                           dtLastLockoutDate);


    //            }

    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetUser(object providerUserKey, bool userIsOnline)");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Unlocks the user.
    //    /// </summary>
    //    /// <param name="username">The username.</param>
    //    /// <returns>true if the membership user was successfully unlocked; 
    //    /// otherwise, false. A value of false is also returned if the user 
    //    /// does not exist in the database. </returns>
    //    public override bool UnlockUser(string username)
    //    {
    //        try
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var account = (from u in session.Users
    //                               where u.UserName == username
    //                               select u).SingleOrDefault();


    //                if (account == null)
    //                    return false;

    //                account.IsLockedOut = false;
    //                account.LastLockoutDate = DateTime.Now;
    //                session.Update(account);

    //                return true;
    //            }
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "UnlockUser");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Gets the user name associated with the specified e-mail address.
    //    /// </summary>
    //    /// <param name="email">The e-mail address to search for.</param>
    //    /// <returns>
    //    /// The user name associated with the specified e-mail address. If no match is found, return null.
    //    /// </returns>
    //    public override string GetUserNameByEmail(string email)
    //    {
    //        try
    //        {


    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var account = (from u in session.Users
    //                               where u.Email == email
    //                               select u).SingleOrDefault();


    //                if (account == null)
    //                {
    //                    //throw new ProviderException("Invalid user name or non-existent user account");
    //                    return null;
    //                }

    //                return account.UserName;

    //            }


    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetUserNameByEmail");
    //            throw new ProviderException(_exceptionMessage);
    //        }
    //    }

    //    /// <summary>
    //    /// Resets a user's password to a new, automatically generated password.
    //    /// </summary>
    //    /// <param name="username">The user to reset the password for.</param>
    //    /// <param name="answer">The password answer for the specified user.</param>
    //    /// <returns>The new password for the specified user.</returns>
    //    public override string ResetPassword(string username, string answer)
    //    {
    //        if (!(EnablePasswordReset))
    //            throw new NotSupportedException("Password reset not enabled");

    //        try
    //        {


    //            using (var session = new MongoSession(_connectionString))
    //            {
    //                var account = (from u in session.Users
    //                               where u.UserName == username
    //                               select u).SingleOrDefault();


    //                if (account == null)
    //                    throw new ProviderException("Invalid user name or non-existent user account");

    //                if (answer == null && RequiresQuestionAndAnswer)
    //                {
    //                    UpdateFailureCount(account.UserId, "PasswordAnswer");
    //                    throw new ProviderException("Password required for reset");
    //                }

    //                string newPassword = Membership.GeneratePassword(_newPasswordLength, MinRequiredNonAlphanumericCharacters);
    //                ValidatePasswordEventArgs Args = new ValidatePasswordEventArgs(username, newPassword, true);
    //                OnValidatingPassword(Args);
    //                if (Args.Cancel)
    //                {
    //                    if (!(Args.FailureInformation == null))
    //                        throw Args.FailureInformation;
    //                    else
    //                        throw new MembershipPasswordException("Password reset cancelled");
    //                }


    //                string passwordKey = String.Empty;
    //                MembershipPasswordFormat format;

    //                if (account.IsLockedOut)
    //                    throw new MembershipPasswordException("Invalid operation. User is locked out");

    //                object passwordAnswer = account.PasswordAnswer;
    //                passwordKey = account.PasswordSalt;
    //                format = (MembershipPasswordFormat)account.PasswordFormat;

    //                if (RequiresQuestionAndAnswer)
    //                {
    //                    if (!CheckPassword(answer, (string)passwordAnswer, passwordKey, format))
    //                    {
    //                        UpdateFailureCount(account.UserId, "PasswordAnswer");
    //                        throw new MembershipPasswordException("Incorrect password answer");
    //                    }
    //                }


    //                account.Password = EncodePassword(newPassword, account.PasswordFormat, passwordKey);
    //                account.PasswordChangedDate = DateTime.Now;
    //                session.Update(account);

    //                //if (rows != 1)
    //                //   throw new MembershipPasswordException("Error resetting password"););

    //                return newPassword;


    //            }

    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "ResetPassword");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Updates information about a user in the data source.
    //    /// </summary>
    //    /// <param name="user">A <see cref="T:System.Web.Security.MembershipUser"/> object 
    //    /// that represents the user to update and the updated information for the user.</param>
    //    public override void UpdateUser(MembershipUser user)
    //    {
    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var account = (from u in session.Users
    //                               where u.UserName == user.UserName
    //                               select u).SingleOrDefault();


    //                if (account == null)
    //                    throw new ProviderException("Invalid user name or non-existent user account");

    //                account.Email = user.Email;
    //                account.IsConfirmed = user.IsApproved;
    //                account.LastLoginDate = user.LastLoginDate;
    //                user.LastActivityDate = user.LastActivityDate;

    //                session.Update(account);

    //            }


    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "UpdateUser");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    /// <summary>
    //    /// Verifies that the specified user name and password exist in the data source.
    //    /// </summary>
    //    /// <param name="username">The name of the user to validate.</param>
    //    /// <param name="password">The password for the specified user.</param>
    //    /// <returns>
    //    /// true if the specified username and password are valid; otherwise, false.
    //    /// </returns>
    //    public override bool ValidateUser(string username, string password)
    //    {
    //        bool isValid = false;
    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var user = (from u in session.Users
    //                            where u.UserName == username
    //                            select u).SingleOrDefault();


    //                if (user == null) return false;

    //                if (user.IsLockedOut) return false;

    //                string pwd = user.Password;
    //                string passwordKey = user.PasswordSalt;
    //                MembershipPasswordFormat format = (MembershipPasswordFormat)user.PasswordFormat;

    //                bool isConfirmed = user.IsConfirmed;

    //                if (!CheckPassword(password, pwd, passwordKey, format))
    //                    UpdateFailureCount(user.UserId, "Password");
    //                else if (isConfirmed)
    //                {
    //                    isValid = true;
    //                    DateTime currentDate = DateTime.Now;

    //                    user.LastActivityDate = currentDate;
    //                    user.LastLoginDate = currentDate;

    //                    session.Update(user);

    //                }

    //            }


    //            return isValid;
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "ValidateUser");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    public override bool ValidateUser(string username, string password)
    //    {
    //        if (string.IsNullOrEmpty(username))
    //        {
    //            throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "username");
    //        }
    //        if (string.IsNullOrEmpty(password))
    //        {
    //            throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "password");
    //        }

    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = VerifyUserNameHasConfirmedAccount(session, username, throwException: false);
    //            if (user == null)
    //            {
    //                return false;
    //            }
    //            else
    //            {
    //                return CheckPassword(db, userId, password);
    //            }
    //        }
    //    }

    //    /// <summary>
    //    /// Gets a collection of membership users where the user name contains the specified user name to match.
    //    /// </summary>
    //    /// <param name="usernameToMatch">The user name to search for.</param>
    //    /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param>
    //    /// <param name="pageSize">The size of the page of results to return.</param>
    //    /// <param name="totalRecords">The total number of matched users.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
    //    /// </returns>
    //    public override MembershipUserCollection FindUsersByName(string usernameToMatch,
    //                                     int pageIndex, int pageSize, out int totalRecords)
    //    {
    //        return GetUsers(usernameToMatch, null, pageIndex, pageSize, out totalRecords);
    //    }

    //    /// <summary>
    //    /// Gets a collection of membership users where the e-mail address contains the specified e-mail address to match.
    //    /// </summary>
    //    /// <param name="emailToMatch">The e-mail address to search for.</param>
    //    /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param>
    //    /// <param name="pageSize">The size of the page of results to return.</param>
    //    /// <param name="totalRecords">The total number of matched users.</param>
    //    /// <returns>
    //    /// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
    //    /// </returns>
    //    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex,
    //                                                              int pageSize, out int totalRecords)
    //    {
    //        return GetUsers(null, emailToMatch, pageIndex, pageSize, out totalRecords);
    //    }

    //    #endregion

    //    #region Private Methods

    //    private MembershipAccount GetUserByName(string username)
    //    {

    //        using (var session = new MongoSession(_connectionString))
    //        {

    //            var user = (from u in session.Users
    //                        where u.UserName == username
    //                        select u).SingleOrDefault();


    //            return user;

    //        }

    //    }


    //    private MembershipAccount GetUserById(int userid)
    //    {

    //        using (var session = new MongoSession(_connectionString))
    //        {

    //            var user = (from u in session.Users
    //                        where u.UserId == userid
    //                        select u).SingleOrDefault();


    //            return user;

    //        }

    //    }

    //    private void WriteToEventLog(Exception e, string action)
    //    {
    //        EventLog log = new EventLog();
    //        log.Source = _eventSource;
    //        log.Log = _eventLog;
    //        string message = "An exception occurred communicating with the data source." +
    //                         Environment.NewLine + Environment.NewLine;
    //        message += "Action: " + action + Environment.NewLine + Environment.NewLine;
    //        message += "Exception: " + e;
    //        log.WriteEntry(message);
    //    }


    //    private string UnEncodePassword(string encodedPassword, MembershipPasswordFormat format)
    //    {
    //        //string password = encodedPassword;
    //        //if (format == MembershipPasswordFormat.Clear)
    //        //    return encodedPassword;
    //        //else if (format == MembershipPasswordFormat.Encrypted)
    //        //    return Encoding.Unicode.GetString(DecryptPassword(
    //        //        Convert.FromBase64String(password)));
    //        //else if (format == MembershipPasswordFormat.Hashed)
    //        //    throw new ProviderException("Cannot decode hashed password");

    //        //else
    //        //    throw new ProviderException("Unsupported password format");


    //        int _passwordFormat = (int)format;

    //        switch (_passwordFormat)
    //        {
    //            case 0:
    //                {
    //                    return encodedPassword;
    //                }
    //            case 1:
    //                {
    //                    throw new ProviderException("Cannot decode hashed password");
    //                }
    //            default:
    //                {
    //                    byte[] passwordBytes = Convert.FromBase64String(encodedPassword);
    //                    byte[] array = this.DecryptPassword(passwordBytes);
    //                    if (array == null)
    //                    {
    //                        return null;
    //                    }
    //                    return Encoding.Unicode.GetString(array, 16, array.Length - 16);
    //                }
    //        }

    //    }

    //    private string GetPasswordKey()
    //    {
    //        RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
    //        byte[] key = new byte[16];
    //        cryptoProvider.GetBytes(key);
    //        return Convert.ToBase64String(key);
    //    }

    //    /// <summary>
    //    /// this method is only necessary because early versions of Mono did not support
    //    /// the HashAlgorithmType property
    //    /// </summary>
    //    /// <param name="bytes"></param>
    //    /// <returns></returns>
    //    private string HashPasswordBytes(byte[] bytes)
    //    {
    //        HashAlgorithm hash = HashAlgorithm.Create(Membership.HashAlgorithmType);
    //        return Convert.ToBase64String(hash.ComputeHash(bytes));
    //    }


    //    private HashAlgorithm GetHashAlgorithm()
    //    {

    //        return HashAlgorithm.Create(Membership.HashAlgorithmType);

    //        //if (this.s_HashAlgorithm != null)
    //        //{
    //        //    return HashAlgorithm.Create(Membership.HashAlgorithmType);
    //        //    //return HashAlgorithm.Create(this.s_HashAlgorithm);
    //        //}
    //        //string text = Membership.HashAlgorithmType;
    //        //if (this._LegacyPasswordCompatibilityMode == MembershipPasswordCompatibilityMode.Framework20
    //        //    && !Membership.IsHashAlgorithmFromMembershipConfig
    //        //    && text != "MD5")
    //        //{
    //        //    text = "SHA1";
    //        //}
    //        //HashAlgorithm hashAlgorithm = HashAlgorithm.Create(text);
    //        //if (hashAlgorithm == null)
    //        //{
    //        //    RuntimeConfig.GetAppConfig().Membership.ThrowHashAlgorithmException();
    //        //}
    //        //this.s_HashAlgorithm = text;
    //        //return hashAlgorithm;
    //    }



    //    private string EncodePassword(string password, int passwordFormat, string salt)
    //    {

    //        if (password == null)
    //            return null;
    //        if (passwordFormat == 0)
    //            return password;

    //        byte[] bytes = Encoding.Unicode.GetBytes(password);
    //        byte[] array = Convert.FromBase64String(salt);
    //        byte[] inArray = null;
    //        if (passwordFormat == 1)
    //        {
    //            HashAlgorithm hashAlgorithm = this.GetHashAlgorithm();
    //            if (hashAlgorithm is KeyedHashAlgorithm)
    //            {
    //                KeyedHashAlgorithm keyedHashAlgorithm = (KeyedHashAlgorithm)hashAlgorithm;
    //                if (keyedHashAlgorithm.Key.Length == array.Length)
    //                {
    //                    keyedHashAlgorithm.Key = array;
    //                }
    //                else
    //                {
    //                    if (keyedHashAlgorithm.Key.Length < array.Length)
    //                    {
    //                        byte[] array2 = new byte[keyedHashAlgorithm.Key.Length];
    //                        Buffer.BlockCopy(array, 0, array2, 0, array2.Length);
    //                        keyedHashAlgorithm.Key = array2;
    //                    }
    //                    else
    //                    {
    //                        byte[] array3 = new byte[keyedHashAlgorithm.Key.Length];
    //                        int num;
    //                        for (int i = 0; i < array3.Length; i += num)
    //                        {
    //                            num = Math.Min(array.Length, array3.Length - i);
    //                            Buffer.BlockCopy(array, 0, array3, i, num);
    //                        }
    //                        keyedHashAlgorithm.Key = array3;
    //                    }
    //                }
    //                inArray = keyedHashAlgorithm.ComputeHash(bytes);
    //            }
    //            else
    //            {
    //                byte[] array4 = new byte[array.Length + bytes.Length];
    //                Buffer.BlockCopy(array, 0, array4, 0, array.Length);
    //                Buffer.BlockCopy(bytes, 0, array4, array.Length, bytes.Length);
    //                inArray = hashAlgorithm.ComputeHash(array4);
    //            }
    //        }
    //        else
    //        {
    //            byte[] array5 = new byte[array.Length + bytes.Length];
    //            Buffer.BlockCopy(array, 0, array5, 0, array.Length);
    //            Buffer.BlockCopy(bytes, 0, array5, array.Length, bytes.Length);
    //            inArray = this.EncryptPassword(array5);
    //        }

    //        return Convert.ToBase64String(inArray);
    //    }


    //    private void UpdateFailureCount(int userId, string failureType)
    //    {

    //        DateTime windowStart = new DateTime();
    //        int failureCount = 0;
    //        try
    //        {

    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                var user = (from u in session.Users
    //                            where u.UserId == userId
    //                            select u).SingleOrDefault();


    //                if (failureType == "Password")
    //                {
    //                    failureCount = user.FailedPasswordAttemptCount;
    //                    windowStart = user.FailedPasswordAttemptWindowStart;
    //                }
    //                if (failureType == "PasswordAnswer")
    //                {
    //                    failureCount = user.FailedPasswordAnswerAttemptCount;
    //                    windowStart = user.FailedPasswordAnswerAttemptWindowStart;
    //                }


    //                DateTime windowEnd = windowStart.AddMinutes(PasswordAttemptWindow);
    //                if (failureCount == 0 || DateTime.Now > windowEnd)
    //                {
    //                    if (failureType == "Password")
    //                    {

    //                        user.FailedPasswordAttemptCount = 1;
    //                        user.FailedPasswordAttemptWindowStart = DateTime.Now;

    //                    }
    //                    if (failureType == "PasswordAnswer")
    //                    {
    //                        user.FailedPasswordAnswerAttemptCount = 1;
    //                        user.FailedPasswordAnswerAttemptWindowStart = DateTime.Now;
    //                    }


    //                    session.Update(user);

    //                    //if (rows < 0)
    //                    //  throw new ProviderException(Resources.UnableToUpdateFailureCount);

    //                }
    //                else
    //                {
    //                    failureCount += 1;
    //                    if (failureCount >= MaxInvalidPasswordAttempts)
    //                    {

    //                        user.IsLockedOut = true;
    //                        user.LastLockoutDate = DateTime.Now;
    //                        session.Update(user);

    //                        //if (rows < 0)
    //                        //  throw new ProviderException(Resources.UnableToLockOutUser);

    //                    }
    //                    else
    //                    {
    //                        if (failureType == "Password")
    //                        {

    //                            user.FailedPasswordAttemptCount = failureCount;

    //                        }
    //                        if (failureType == "PasswordAnswer")
    //                        {
    //                            user.FailedPasswordAnswerAttemptCount = failureCount;
    //                        }

    //                        session.Update(user);

    //                        //if (rows < 0)
    //                        //  throw new ProviderException("Unable to update failure count.");

    //                    }
    //                }

    //            }


    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "UpdateFailureCount");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }

    //    private bool CheckPassword(MongoCollection collection, int userId, string password)
    //    {
    //        string hashedPassword = GetHashedPassword(db, userId);
    //        bool verificationSucceeded = (hashedPassword != null && Crypto.VerifyHashedPassword(hashedPassword, password));
    //        if (verificationSucceeded)
    //        {
    //            // Reset password failure count on successful credential check
    //            db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordFailuresSinceLastSuccess = 0 WHERE (UserId = @0)", userId);
    //        }
    //        else
    //        {
    //            int failures = GetPasswordFailuresSinceLastSuccess(db, userId);
    //            if (failures != -1)
    //            {
    //                db.Execute(@"UPDATE " + MembershipTableName + " SET PasswordFailuresSinceLastSuccess = @1, LastPasswordFailureDate = @2 WHERE (UserId = @0)", userId, failures + 1, DateTime.UtcNow);
    //            }
    //        }
    //        return verificationSucceeded;
    //    }

    //    private bool CheckPassword(string password, string dbpassword,
    //        string passwordKey, MembershipPasswordFormat format)
    //    {


    //        //string encodedPasswd1 = EncodePassword2(password, (int)PasswordFormat,passwordKey); //; EncodePassword(password, passwordKey, format);
    //        //string encodedPasswd2 = EncodePassword2(password, (int)PasswordFormat, passwordKey);

    //        //if (!encodedPasswd1.Equals(encodedPasswd2))
    //        //{
    //        //    throw new ProviderException(string.Format("Funny=>salt->{0} \n ,password->{1} \n,"
    //        //    + "db password->{2} \n,encodedPassword1->{3} , \n encodedPassword2->{4}, \n format->{5}",
    //        //    passwordKey, password,dbpassword, encodedPasswd1, encodedPasswd2,format));

    //        //}

    //        var encodedPassword = EncodePassword(password, (int)format, passwordKey);

    //        bool isPasswordCorrect = false;

    //        //if (!dbpassword.Equals(encodedPassword))
    //        //{
    //        //    throw new ProviderException(string.Format("password->{0} , \n db password->{1} \n, salt->{2} \n ,"
    //        //    + "encodedPassword->{3}",
    //        //     password, dbpassword, passwordKey, encodedPassword));
    //        //}

    //        isPasswordCorrect = dbpassword.Equals(encodedPassword);

    //        //if (isPasswordCorrect == false)
    //        //{
    //        //    //return false;
    //        //    throw new ProviderException(string.Format("check password : isPasswordcorrect->{0} ," +
    //        //   ", passwordFromDb->{1}, encodedPassword->{2}",
    //        //   isPasswordCorrect, dbpassword, encodedPassword));

    //        //}


    //        return isPasswordCorrect;//encodedPassword == dbpassword;
    //    }

    //    private void GetPasswordInfo(int userId, out string passwordKey, out MembershipPasswordFormat passwordFormat)
    //    {

    //        using (var session = new MongoSession(_connectionString))
    //        {

    //            var user = (from u in session.Users
    //                        where u.UserId == userId
    //                        select u).SingleOrDefault();

    //            passwordKey = user.PasswordSalt;
    //            passwordFormat = (MembershipPasswordFormat)user.PasswordFormat;


    //        }


    //    }

    //    private MembershipUserCollection GetUsers(string username, string email,
    //        int pageIndex, int pageSize, out int totalRecords)
    //    {
    //        MembershipUserCollection users = new MembershipUserCollection();
    //        try
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {

    //                IQueryable<MembershipAccount> members = from u in session.Users
    //                                                        select u;

    //                if (!string.IsNullOrEmpty(email))
    //                    members = members.Where(u => u.LoweredEmail.Contains(email.ToLowerInvariant()));

    //                if (!string.IsNullOrEmpty(username))
    //                    members = members.Where(u => u.LoweredUserName.Contains(username.ToLowerInvariant()));


    //                var found = members.Skip(pageIndex).Take(pageSize);
    //                totalRecords = members.Count();

    //                foreach (var user in found)
    //                {
    //                    string _username, _email, passwordQuestion;
    //                    bool isApproved;
    //                    DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
    //                    int? userId;
    //                    bool isLockedOut;
    //                    DateTime dtLastLockoutDate;

    //                    _username = user.UserName;
    //                    _email = user.Email;
    //                    passwordQuestion = user.PasswordQuestion;
    //                    isApproved = user.IsConfirmed;
    //                    dtCreate = user.CreateDate.ToLocalTime();
    //                    dtLastLogin = user.LastLoginDate.ToLocalTime();
    //                    dtLastActivity = user.LastActivityDate.ToLocalTime();
    //                    dtLastPassChange = user.PasswordChangedDate.ToLocalTime();
    //                    userId = user.UserId;
    //                    isLockedOut = user.IsLockedOut;
    //                    dtLastLockoutDate = user.LastLockoutDate.ToLocalTime();

    //                    users.Add(new MembershipUser(this.Name,
    //                                                   _username,
    //                                                   userId,
    //                                                   _email,
    //                                                   passwordQuestion,
    //                                                   string.Empty,
    //                                                   isApproved,
    //                                                   isLockedOut,
    //                                                   dtCreate,
    //                                                   dtLastLogin,
    //                                                   dtLastActivity,
    //                                                   dtLastPassChange,
    //                                                   dtLastLockoutDate));
    //                }

    //            }
    //            return users;
    //        }
    //        catch (Exception e)
    //        {
    //            if (WriteExceptionsToEventLog)
    //                WriteToEventLog(e, "GetUsers");
    //            throw new ProviderException(_exceptionMessage, e);
    //        }
    //    }


    //    private void ValidateQA(string question, string answer)
    //    {
    //        if (RequiresQuestionAndAnswer && String.IsNullOrEmpty(question))
    //            throw new ArgumentException("Password question supplied is invalid.");
    //        if (RequiresQuestionAndAnswer && String.IsNullOrEmpty(answer))
    //            throw new ArgumentException("Password answer supplied is invalid.");
    //    }

    //    private bool ValidatePassword(string password, string argumentName, bool throwExceptions)
    //    {
    //        string exceptionString = null;
    //        object correctValue = MinRequiredPasswordLength;

    //        if (password.Length < MinRequiredPasswordLength)
    //            exceptionString = "The length of parameter '{0}' needs to be greater or equal to '{1}'.";
    //        else
    //        {
    //            int count = 0;
    //            foreach (char c in password)
    //                if (!char.IsLetterOrDigit(c))
    //                    count++;
    //            if (count < MinRequiredNonAlphanumericCharacters)
    //                exceptionString = "Non alpha numeric characters in '{0}' needs to be greater than or equal to '{1}'.";
    //            correctValue = MinRequiredNonAlphanumericCharacters;
    //        }

    //        if (exceptionString != null)
    //        {
    //            if (throwExceptions)
    //                throw new ArgumentException(
    //                    string.Format(exceptionString, argumentName, correctValue),
    //                    argumentName);
    //            else
    //                return false;
    //        }

    //        if (PasswordStrengthRegularExpression.Length > 0)
    //            if (!Regex.IsMatch(password, PasswordStrengthRegularExpression))
    //                return false;

    //        return true;
    //    }

    //    private DateTime RoundToSeconds(DateTime dt)
    //    {
    //        return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
    //    }

    //    #endregion

    //    public override bool ConfirmAccount(string accountConfirmationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override bool ConfirmAccount(string userName, string accountConfirmationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, System.Collections.Generic.IDictionary<string, object> values)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override bool DeleteAccount(string userName)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override DateTime GetCreateDate(string userName)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override DateTime GetLastPasswordFailureDate(string userName)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override DateTime GetPasswordChangedDate(string userName)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override int GetPasswordFailuresSinceLastSuccess(string userName)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    public override int GetUserIdFromPasswordResetToken(string token)
    //    {
    //        throw new NotImplementedException();
    //    }

    //    private MembershipAccount VerifyUserNameHasConfirmedAccount(MongoSession session, string username, bool throwException)
    //    {
    //        var user = session.Users.FirstOrDefault(x => x.UserName == username);
    //        if (user == null)
    //        {
    //            if (throwException)
    //            {
    //                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "Security No User Found", username));
    //            }
    //            else
    //            {
    //                return null;
    //            }
    //        }

    //        int result = session.Users.Count(x => x.UserId == user.UserId && x.IsConfirmed == true);
    //        if (result == 0)
    //        {
    //            if (throwException)
    //            {
    //                throw new InvalidOperationException(String.Format(CultureInfo.CurrentCulture, "Security No Account Found", username));
    //            }
    //            else
    //            {
    //                return null;
    //            }
    //        }
    //        return user;
    //    }

    //    private static string GenerateToken()
    //    {
    //        using (var prng = new RNGCryptoServiceProvider())
    //        {
    //            return GenerateToken(prng);
    //        }
    //    }

    //    internal static string GenerateToken(RandomNumberGenerator generator)
    //    {
    //        byte[] tokenBytes = new byte[TokenSizeInBytes];
    //        generator.GetBytes(tokenBytes);
    //        return HttpServerUtility.UrlTokenEncode(tokenBytes);
    //    }

    //    // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
    //    public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
    //    {
    //        //VerifyInitialized();
    //        if (string.IsNullOrEmpty(userName))
    //        {
    //            throw new ArgumentException("Argument cannot be null or empty", "userName");
    //        }
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = VerifyUserNameHasConfirmedAccount(session, userName, throwException: true);

    //            string token = session
    //                .Users
    //                .Where(x => x.UserId == user.UserId && x.PasswordVerificationTokenExpirationDate > DateTime.UtcNow)
    //                .Select(x => x.PasswordVerificationToken)
    //                .FirstOrDefault();

    //            if (token == null)
    //            {
    //                token = GenerateToken();

    //                user.PasswordVerificationToken = token;
    //                user.PasswordVerificationTokenExpirationDate = DateTime.UtcNow.AddMinutes(tokenExpirationInMinutesFromNow);
    //                session.Update<MembershipAccount>(user);
    //                //if (rows != 1)
    //                //{
    //                //    throw new ProviderException(WebDataResources.Security_DbFailure);
    //                //}
    //            }
    //            else
    //            {
    //                // TODO: should we update expiry again?
    //            }
    //            return token;
    //        }
    //    }

    //    // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
    //    public override bool IsConfirmed(string userName)
    //    {
    //        if (string.IsNullOrEmpty(userName))
    //        {
    //            throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "userName");
    //        }

    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = VerifyUserNameHasConfirmedAccount(session, userName, throwException: false);
    //            return (user != null);
    //        }
    //    }

    //    // Inherited from ExtendedMembershipProvider ==> Simple Membership MUST be enabled to use this method
    //    public override bool ResetPasswordWithToken(string token, string newPassword)
    //    {
    //        if (string.IsNullOrEmpty(newPassword))
    //        {
    //            throw new ArgumentException("Argument_Cannot_Be_Null_Or_Empty", "newPassword");
    //        }
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = session.Users.FirstOrDefault(x => x.PasswordVerificationToken == token && x.PasswordVerificationTokenExpirationDate > DateTime.UtcNow);
    //            if (user != null)
    //            {
    //                bool success = SetPassword(session, user, newPassword);
    //                if (success)
    //                {
    //                    user.PasswordVerificationToken = string.Empty;

    //                    try
    //                    {
    //                        session.Update(user);
    //                    }
    //                    catch (Exception)
    //                    {
    //                        throw new ProviderException("Security_DbFailure");
    //                    }
    //                }
    //                return success;
    //            }
    //            else
    //            {
    //                return false;
    //            }
    //        }
    //    }

    //    private bool SetPassword(MongoSession session, MembershipAccount user, string newPassword)
    //    {
    //        // retrieve the existing key and format for this user
    //        try
    //        {
    //            string passwordKey;
    //            MembershipPasswordFormat passwordFormat;

    //            GetPasswordInfo(user.UserId, out passwordKey, out passwordFormat);

    //            user.Password = EncodePassword(newPassword, (int)passwordFormat, passwordKey);
    //            user.PasswordChangedDate = DateTime.Now;
    //            session.Update(user);

    //            return true;
    //        }
    //        catch (Exception)
    //        {
    //            return false;
    //        }
    //    }

    //    public override ICollection<WebMatrix.WebData.OAuthAccountData> GetAccountsForUser(string userName)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = session.Users.FirstOrDefault(x => x.UserName == userName);
    //            if (user != null)
    //            {

    //                ICollection<OAuthAccountDataEmbedded> records = session
    //                    .OAuthAccountData
    //                    .Where(x => x.UserId == user.UserId)
    //                    .ToList();

    //                ICollection<WebMatrix.WebData.OAuthAccountData> accounts = new List<WebMatrix.WebData.OAuthAccountData>();
    //                if (records != null)
    //                {
    //                    foreach (var item in records)
    //                    {
    //                        WebMatrix.WebData.OAuthAccountData data = new WebMatrix.WebData.OAuthAccountData(item.Provider, item.ProviderUserId);
    //                        accounts.Add(data);
    //                    }

    //                    return accounts;
    //                }
    //            }
    //        }

    //        return new WebMatrix.WebData.OAuthAccountData[0];
    //    }

    //    /// <summary>
    //    /// Deletes the OAuth token from the backing store from the database.
    //    /// </summary>
    //    /// <param name="token">The token to be deleted.</param>
    //    public override void DeleteOAuthToken(string token)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            IMongoQuery query = Query.EQ("_id", token);
    //            session.Delete<OAuthToken>(query);
    //        }
    //    }

    //    /// <summary>
    //    /// Replaces the request token with access token and secret.
    //    /// </summary>
    //    /// <param name="requestToken">The request token.</param>
    //    /// <param name="accessToken">The access token.</param>
    //    /// <param name="accessTokenSecret">The access token secret.</param>
    //    public override void ReplaceOAuthRequestTokenWithAccessToken(string requestToken, string accessToken, string accessTokenSecret)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            // insert new record
    //            DeleteOAuthToken(requestToken);
    //        }
    //        // Although there are two different types of tokens, request token and access token,
    //        // we treat them the same in database records.
    //        StoreOAuthRequestToken(accessToken, accessTokenSecret);

    //    }

    //    public override void StoreOAuthRequestToken(string requestToken, string requestTokenSecret)
    //    {
    //        string existingSecret = GetOAuthTokenSecret(requestToken);
    //        if (existingSecret != null)
    //        {
    //            if (existingSecret == requestTokenSecret)
    //            {
    //                // the record already exists
    //                return;
    //            }

    //            using (var session = new MongoSession(_connectionString))
    //            {
    //                var t = session.OAuthTokens.FirstOrDefault(x => x.Token == requestToken);
    //                t.Secret = requestTokenSecret;
    //                session.Update(t);
    //            }
    //        }
    //        else
    //        {
    //            using (var session = new MongoSession(_connectionString))
    //            {
    //                // insert new record
    //                var t = new OAuthToken();
    //                t.Token = requestToken;
    //                t.Secret = requestTokenSecret;

    //                try
    //                {
    //                    session.Add(t);
    //                }
    //                catch (Exception)
    //                {
    //                    throw new ProviderException("SimpleMembership_FailToStoreOAuthToken");
    //                }
    //            }
    //        }
    //    }

    //    public override string GetOAuthTokenSecret(string token)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            // Note that token is case-sensitive
    //            var secret = session.OAuthTokens.FirstOrDefault(x => x.Token == token);
    //            return secret == null ? null : secret.Secret;
    //        }
    //    }

    //    public override int GetUserIdFromOAuth(string provider, string providerUserId)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {

    //            var data = session.OAuthAccountData.ToList().FirstOrDefault(x => x.Provider == provider && x.ProviderUserId == providerUserId);
    //            if (data != null)
    //            {
    //                return data.UserId;
    //            }

    //            return -1;
    //        }
    //    }

    //    public override string GetUserNameFromId(int userId)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            var user = session.Users.FirstOrDefault(x => x.UserId == userId);
    //            return user == null ? null : user.UserName;
    //        }
    //    }

    //    public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
    //    {
    //        if (string.IsNullOrEmpty(userName))
    //        {
    //            throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
    //        }

    //        var user = GetUser(userName);
    //        if (user == null)
    //        {
    //            throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
    //        }

    //        var oldUserId = GetUserIdFromOAuth(provider, providerUserId);
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            if (oldUserId == -1)
    //            {
    //                // account doesn't exist. create a new one.
    //                var aouthData = new OAuthAccountDataEmbedded(provider, providerUserId);
    //                aouthData.UserId = user.UserId;

    //                try
    //                {
    //                    session.Add(aouthData);
    //                }
    //                catch (Exception)
    //                {
    //                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
    //                }
    //            }
    //            else
    //            {
    //                // account already exist. update it
    //                var aouthData = session.OAuthAccountData.ToList().FirstOrDefault(x => x.Provider == provider && x.ProviderUserId == providerUserId);
    //                aouthData.UserId = user.UserId;
    //                try
    //                {
    //                    session.Update(aouthData);
    //                }
    //                catch (Exception)
    //                {
    //                    throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
    //                }
    //            }
    //        }
    //    }

    //    public override void DeleteOAuthAccount(string provider, string providerUserId)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            IMongoQuery query = Query.And(Query.EQ("Provider", provider), Query.EQ("ProviderUserId", providerUserId));
    //            try
    //            {
    //                session.Delete<OAuthAccountData>(query);
    //            }
    //            catch (Exception)
    //            {
    //                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
    //            }
    //        }
    //    }

    //    private MembershipAccount GetUser(string username)
    //    {
    //        using (var session = new MongoSession(_connectionString))
    //        {
    //            return session.Users.FirstOrDefault(x => x.UserName == username);
    //        }
    //    }


    //}

}
