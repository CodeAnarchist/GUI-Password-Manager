using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;

namespace PWEngine
{
    public partial class MainWindow : Window
    {
        private const string LogFileName = "passwords.log";
        private const string DatabaseFileName = "passwords.json";
        private const string MasterPasswordFileName = "masterpassword.bin";
        private Dictionary<string, PasswordEntry> passwordDatabase = new Dictionary<string, PasswordEntry>();
        private byte[] masterPasswordHash = null;
        bool resetDatabase = false;

        public MainWindow()
        {

            if (File.Exists(MasterPasswordFileName))
            {
                bool verified = false;
                while (!verified)
                {
                    string masterPassword = PromptForMasterPassword();
                    masterPasswordHash = HashPassword(masterPassword);

                    if (VerifyMasterPassword(masterPassword))
                    {
                        Console.WriteLine("correct master");
                        verified = true;
                        InitializeComponent();

                    }
                    else
                    {
                        MessageBox.Show("Invalid master password. Please try again.");
                        this.Close();
                        return;
                    }
                }
            }
            else
            {
                MessageBox.Show("No master password found. Creating a new one...");
                string newMasterPassword = PromptForMasterPassword();
                masterPasswordHash = HashPassword(newMasterPassword);
                File.WriteAllBytes(MasterPasswordFileName, masterPasswordHash);
                SaveDatabase();
                InitializeComponent();

            }
            LoadDatabase(resetDatabase);
        }

        private string PromptForMasterPassword()
        {
            MasterPasswordWindow masterPasswordWindow = new MasterPasswordWindow();
            masterPasswordWindow.ShowDialog();
            return masterPasswordWindow.MasterPassword;


        }
        private void LoadDatabase(bool reset)
        {
            if (reset || !File.Exists(DatabaseFileName))
            {
                passwordDatabase = new Dictionary<string, PasswordEntry>();
                SaveDatabase();
                MessageBox.Show("Database reset or created.");
            }
            else
            {
                try
                {
                    string databaseJson = File.ReadAllText(DatabaseFileName);
                    passwordDatabase = JsonConvert.DeserializeObject<Dictionary<string, PasswordEntry>>(databaseJson);
                    DecryptPasswords();
                   
                }
                catch (JsonException)
                {
                    MessageBox.Show("Error loading the database. The format may be corrupted.");
                }
            }
        }

        private void SaveDatabase()
        {
            EncryptPasswords();
            string databaseJson = JsonConvert.SerializeObject(passwordDatabase, Formatting.Indented);
            File.WriteAllText(DatabaseFileName, databaseJson);
            
        }

        private void EncryptPasswords()
        {
            foreach (var entry in passwordDatabase)
            {
                string decryptedPassword = DecryptString(entry.Value.Password, entry.Value.Website, entry.Value.Salt);
                entry.Value.Password = EncryptString(decryptedPassword, entry.Value.Website);
            }
        }

        private void DecryptPasswords()
        {
            foreach (var entry in passwordDatabase)
            {
                string decryptedPassword = (entry.Value.Password.Replace(entry.Value.Salt.ToString(),""), entry.Value.Website, entry.Value.Salt).ToString().Replace(entry.Value.Salt.ToString(), "");
                entry.Value.Password = decryptedPassword.Replace(entry.Value.Salt, "");
            }
        }

        private bool VerifyMasterPassword(string inputPassword)
        {
            masterPasswordHash = File.ReadAllBytes(MasterPasswordFileName);
            byte[] inputPasswordHash = HashPassword(inputPassword);
            //verify that master pw is equal to master pw hash
            if (StructuralComparisons.StructuralEqualityComparer.Equals(inputPasswordHash, masterPasswordHash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private byte[] HashPassword(string password)
        {
            using (var sha512 = SHA512.Create())
            {
                if (!(password == null))
                    return sha512.ComputeHash(Encoding.UTF8.GetBytes(password));
                else {
                    Application.Current.Shutdown();
                        return null; }
            }
        }

        private string GenerateRandomPassword(int length)
        {
            const string allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=<>?";

            Random rng = new Random();
            char[] password = new char[length];

            for (int i = 0; i < length; i++)
            {
                password[i] = allowedChars[rng.Next(0, allowedChars.Length)];
            }

            LogToFile("Generated a random password");

            return new string(password);
        }

        private string EncryptString(string plainText, string sitePassword)
        {
            using (Aes aesAlg = Aes.Create())
            {
                //derive a key from the master pw and the site password using PBKDF2
                byte[] derivedKey = DeriveKey(masterPasswordHash, Encoding.UTF8.GetBytes(sitePassword));

                aesAlg.Key = derivedKey;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(aesAlg.IV) + Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }

        private string DecryptString(string cipherText, string sitePassword, string salt)
        {
            using (Aes aesAlg = Aes.Create())
            {
                Console.WriteLine(cipherText.Substring(0, 24));
                Console.WriteLine(cipherText);
                byte[] iv = Convert.FromBase64String(cipherText.Substring(0, 24));

                byte[] cipherBytes = Convert.FromBase64String(cipherText.Substring(24));

                //desc key
                byte[] derivedKey = DeriveKey(masterPasswordHash, Encoding.UTF8.GetBytes(sitePassword));

                aesAlg.Key = derivedKey;
                aesAlg.Mode = CipherMode.CFB;
                aesAlg.Padding = PaddingMode.PKCS7;
                //Console.WriteLine(aesAlg.Mode+"  "+ aesAlg.Padding);
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, iv);

                using (MemoryStream msDecrypt = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            // Console.WriteLine(sitePassword+"  "+salt);
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
        private void CopyGeneratePassword_Click(object sender, RoutedEventArgs e)
        {
            string generatedPassword = GeneratedPasswordTextBlock.Text;

            if (!string.IsNullOrWhiteSpace(generatedPassword))
            {
                Clipboard.SetText(generatedPassword.Replace("Generated password: ",""));
                MessageBox.Show("password copied to clipboard.", "Copy", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("There's no password", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private byte[] DeriveKey(byte[] masterKey, byte[] sitePasswordBytes)
        {
            try
            {
                Console.WriteLine(sitePasswordBytes.ToString() + "  " + sitePasswordBytes.Length);
                using (Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(masterKey, sitePasswordBytes, 10000))
                {
                    return deriveBytes.GetBytes(32);
                }
            }
            catch { return sitePasswordBytes; }
        }

        private void LogToFile(string message)
        {
            if (!File.Exists(LogFileName))
            {
                try
                {
                    File.Create(LogFileName).Close();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error creating log file: {ex.Message}");
                    return;
                }
            }
            try
            {
                using (StreamWriter writer = File.AppendText(LogFileName))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}: {message}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error writing to log file: {ex.Message}");
            }

        }
        private static byte[] GenerateSalt()
        {
            byte[] salt = new byte[512]; //4096-bit salt
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }
        private static bool IsPasswordStrong(string password)
        {
            //definition of security critiria
            const int minLength = 8;
            const int minUpperCase = 1;
            const int minLowerCase = 1;
            const int minDigits = 1;
            const int minSpecialChars = 1;

            //minimum length
            if (password.Length < minLength)
            {
                return false;
            }

            //uppercase
            if (password.Count(char.IsUpper) < minUpperCase)
            {
                return false;
            }

            //lowercase
            if (password.Count(char.IsLower) < minLowerCase)
            {
                return false;
            }

            //digits
            if (password.Count(char.IsDigit) < minDigits)
            {
                return false;
            }

            //special characte
            if (password.Count(c => !char.IsLetterOrDigit(c)) < minSpecialChars)
            {
                return false;
            }

            return true;
        }
        private List<PasswordEntry> GetArchivedPasswords()
        {
            List<PasswordEntry> archivedPasswords = new List<PasswordEntry>();

            try
            {
                //load db
                string databaseJson = File.ReadAllText(DatabaseFileName);
                passwordDatabase = JsonConvert.DeserializeObject<Dictionary<string, PasswordEntry>>(databaseJson);

                // Recupera le password dal database e aggiungile all'elenco delle password archiviate
                foreach (var entry in passwordDatabase.Values)
                {
                    archivedPasswords.Add(entry);
                }
            }
            catch (JsonException)
            {
                Console.WriteLine("");
            }

            return archivedPasswords;
        }
        private void UpdateArchiveListView(List<PasswordEntry> archivedPasswords)
        {
            
            PasswordListView.Items.Clear();

            foreach (var entry in archivedPasswords)
            {
                string password = entry.Password;
                //create a viewitem foreach entry in a list
                ListViewItem item = new ListViewItem();
                item.Content = $"Website: {entry.Website}, Username: {entry.Username}";
                Console.WriteLine(password);
                Console.WriteLine(entry.Salt);
                //listener for double click on entry
                item.MouseDoubleClick += (sender, e) =>
                {
                    Console.WriteLine(entry.Password);
                    //show pw
                    ShowPassword(password, entry.Website, entry.Salt);
                };

                //add elemenet to the list
                PasswordListView.Items.Add(item);
            }
        }
        private void ShowPassword(string encryptedPassword, string website, string salt)
        {
            //decrypt
            Console.WriteLine(encryptedPassword);
            string decryptedPassword = DecryptString(encryptedPassword, website, salt).Replace(salt,"");

            if (!string.IsNullOrEmpty(decryptedPassword))
            {
                //show pw in a dialogue box
                Window passwordDialog = new Window
                {
                    Title = "Password",
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterScreen,
                    ResizeMode = ResizeMode.NoResize
                };

                //create text for pw
                TextBox passwordTextBox = new TextBox
                {
                    Text = decryptedPassword,
                    IsReadOnly = true,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(10),
                    TextWrapping = TextWrapping.Wrap
                };

                //create a button
                Button copyButton = new Button
                {
                    Content = "Copy Password",
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Bottom,
                    Margin = new Thickness(10)
                };

                //event listener
                copyButton.Click += (sender, e) =>
                {
                    Clipboard.SetText(decryptedPassword);
                    MessageBox.Show("Password has been copied in the clipboard", "Copy", MessageBoxButton.OK, MessageBoxImage.Information);
                };

                //add controls to the dialogue nbox
                passwordDialog.Content = new StackPanel
                {
                    Children =
        {
            passwordTextBox,
            copyButton
        }
                };

                passwordDialog.ShowDialog();
            }
            else
            {
                MessageBox.Show("Error during decryption", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void AddPassword_Click(object sender, RoutedEventArgs e)
        {
            if (AddPasswordFrame.Visibility == Visibility.Collapsed)
            {
                //hide frame
                HomeScreen.Visibility = Visibility.Collapsed;
                DeletePasswordFrame.Visibility = Visibility.Collapsed;
                ViewArchiveFrame.Visibility = Visibility.Collapsed;
                GeneratePasswordFrame.Visibility = Visibility.Collapsed;
                ViewLogFrame.Visibility = Visibility.Collapsed;
                AddPasswordFrame.Visibility = Visibility.Visible;
            }
            else
            {
                //get form input
                string username = UsernameTextBox.Text;
                string password = PasswordBox.Password;
                string confirmPassword = ConfirmPasswordBox.Password;
                string websiteUrl = WebsiteTextBox.Text;

                if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password) && password == confirmPassword)
                {
                    //Generate a salt
                    byte[] salt = GenerateSalt();

                    if (IsPasswordStrong(password))
                    {
                        MessageBoxResult result = MessageBox.Show("Do you want to save this password", "Save PW", MessageBoxButton.YesNo, MessageBoxImage.Question);

                        if (result == MessageBoxResult.Yes)
                        {
                            //url as key
                            string key = websiteUrl;

                            //concat pw and salt
                            string saltedPassword = password + Convert.ToBase64String(salt);
                            string encryptedPassword = EncryptString(saltedPassword, websiteUrl);

                            //add pw to db
                            passwordDatabase[key] = new PasswordEntry
                            {
                                Username = username,
                                Password = encryptedPassword,
                                Website = websiteUrl,
                                Salt = Convert.ToBase64String(salt)
                            };

                            MessageBox.Show("password has been saved successfully", "Save", MessageBoxButton.OK, MessageBoxImage.Information);
                            LogToFile($"Added pw for: {websiteUrl}");
                            SaveDatabase();
                        }
                    }
                    else
                    {
                        MessageBox.Show("Password is very weak", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
                        MessageBoxResult result = MessageBox.Show("Are you willing to use this password", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

                        if (result == MessageBoxResult.Yes)
                        {
                            string key = websiteUrl;
                            string saltedPassword = password + Convert.ToBase64String(salt);
                            string encryptedPassword = EncryptString(saltedPassword, websiteUrl);

                            //add pw to db
                            passwordDatabase[key] = new PasswordEntry
                            {
                                Username = username,
                                Password = encryptedPassword,
                                Website = websiteUrl,
                                Salt = Convert.ToBase64String(salt)
                            };

                            MessageBox.Show("password has been saved successfully", "Save", MessageBoxButton.OK, MessageBoxImage.Information);
                            LogToFile($"Added pw for: {websiteUrl}");
                            SaveDatabase();
                        }
                    }
                }
                else
                {
                    MessageBox.Show("Username is null or pw and pw confirmation do not correspond", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }


        private void DeletePassword_Click(object sender, RoutedEventArgs e)
        {
            if (DeletePasswordFrame.Visibility == Visibility.Collapsed)
            {
                HomeScreen.Visibility = Visibility.Collapsed;
                AddPasswordFrame.Visibility = Visibility.Collapsed;
                ViewArchiveFrame.Visibility = Visibility.Collapsed;
                GeneratePasswordFrame.Visibility = Visibility.Collapsed;
                ViewLogFrame.Visibility = Visibility.Collapsed;
                DeletePasswordFrame.Visibility = Visibility.Visible;
            }
            else {
            //get website
            string websiteToDelete = DeleteWebsiteTextBox.Text;
                List<PasswordEntry> archivedPasswords = new List<PasswordEntry>();

                try
                {
                    //load db
                    string databaseJson = File.ReadAllText(DatabaseFileName);
                    passwordDatabase = JsonConvert.DeserializeObject<Dictionary<string, PasswordEntry>>(databaseJson);

                    //retrive pw
                    foreach (var entry in passwordDatabase.Values)
                    {
                        archivedPasswords.Add(entry);
                    }
                }
                catch (JsonException)
                {
                    Console.WriteLine("An error has been rised.");
                }
                // Verifica se il sito web è presente nel database
                if (passwordDatabase.ContainsKey(websiteToDelete))
            {
                MessageBoxResult result = MessageBox.Show($"Are you sure to delete this password and its corresponding entry: {websiteToDelete}?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (result == MessageBoxResult.Yes)
                {
                    // Esegui la logica per eliminare la password dal database
                    passwordDatabase.Remove(websiteToDelete);

                    // Aggiorna l'interfaccia utente per riflettere l'eliminazione
                    DeleteWebsiteTextBox.Clear();
                    MessageBox.Show($"{websiteToDelete} password has been deleted successfully", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    SaveDatabase();
                    LogToFile($"Entry deleted: {websiteToDelete}");
                }
            }
            else
            {
                MessageBox.Show($"{websiteToDelete} doesn't exist in the database.", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            }
        }

        private void ViewArchive_Click(object sender, RoutedEventArgs e)
        {
            if (ViewArchiveFrame.Visibility == Visibility.Collapsed)
            {
                HomeScreen.Visibility = Visibility.Collapsed;
                AddPasswordFrame.Visibility = Visibility.Collapsed;
                DeletePasswordFrame.Visibility = Visibility.Collapsed;
                GeneratePasswordFrame.Visibility = Visibility.Collapsed;
                ViewLogFrame.Visibility = Visibility.Collapsed;
                ViewArchiveFrame.Visibility = Visibility.Visible;
                List<PasswordEntry> archivedPasswords = GetArchivedPasswords(); 
                UpdateArchiveListView(archivedPasswords);
            }
        }


        private void GeneratePassword_Click(object sender, RoutedEventArgs e)
        {
            if (GeneratePasswordFrame.Visibility == Visibility.Collapsed)
            {
                HomeScreen.Visibility = Visibility.Collapsed;
                AddPasswordFrame.Visibility = Visibility.Collapsed;
                DeletePasswordFrame.Visibility = Visibility.Collapsed;
                ViewArchiveFrame.Visibility = Visibility.Collapsed;
                ViewLogFrame.Visibility = Visibility.Collapsed;
                GeneratePasswordFrame.Visibility = Visibility.Visible;
            }
            else
            {
                if (int.TryParse(PasswordLengthTextBox.Text, out int passwordLength) && passwordLength > 0)
                {
                    string generatedPassword = GenerateRandomPassword(passwordLength);
                    //GeneratedPasswordTextBlock.Text = generatedPassword;
                    GeneratedPasswordTextBlock.Text = $"Random password: {generatedPassword}";

                }
                else
                {
                    MessageBox.Show("Submit a valid lenght", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
        private void ViewLog_Click(object sender, RoutedEventArgs e)
        {
            HomeScreen.Visibility = Visibility.Collapsed;
            AddPasswordFrame.Visibility = Visibility.Collapsed;
            DeletePasswordFrame.Visibility = Visibility.Collapsed;
            ViewArchiveFrame.Visibility = Visibility.Collapsed;
            ViewLogFrame.Visibility = Visibility.Visible;
            GeneratePasswordFrame.Visibility = Visibility.Collapsed;
            string logContent = ReadLogFromFile(LogFileName);
            LogTextBox.Text = logContent;
        }

        private string ReadLogFromFile(string fileName)
        {
            try
            {
                if (File.Exists(fileName))
                {
                    //read log 
                    return File.ReadAllText(fileName);
                }
                else
                {
                    return "Log doesn't exist";
                }
            }
            catch (Exception ex)
            {
                return $"An error has been rised during the database reading: {ex.Message}";
            }
        }


        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();

        }

        private void SavePassword_Click(object sender, RoutedEventArgs e)
        {
            //get form
            string username = UsernameTextBox.Text;
            string password = PasswordBox.Password;
            string confirmPassword = ConfirmPasswordBox.Password;
            string websiteUrl = WebsiteTextBox.Text;

            if (!string.IsNullOrWhiteSpace(username) && !string.IsNullOrWhiteSpace(password) && password == confirmPassword)
            {
                byte[] salt = GenerateSalt();

                if (IsPasswordStrong(password))
                {
                    MessageBoxResult result = MessageBox.Show("Do you want to save the password?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        //url is the key
                        string key = websiteUrl;

                        // cancat password and salt
                        string saltedPassword = password + Convert.ToBase64String(salt);
                        string encryptedPassword = EncryptString(saltedPassword, websiteUrl);

                        //add pw to db
                        passwordDatabase[key] = new PasswordEntry
                        {
                            Username = username,
                            Password = encryptedPassword,
                            Website = websiteUrl,
                            Salt = Convert.ToBase64String(salt)
                        };

                        MessageBox.Show("Password has been saved successfully", "Save", MessageBoxButton.OK, MessageBoxImage.Information);
                        LogToFile($"Added password: {websiteUrl}");
                        SaveDatabase();

                        // Torna alla pagina principale
                        ShowMainPage();
                    }
                }
                else
                {
                    MessageBoxResult result = MessageBox.Show("Password is very weak, are you sure to use this?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);

                    if (result == MessageBoxResult.Yes)
                    {
                        // Usa l'URL come chiave nel database
                        string key = websiteUrl;

                        // Concatena il salt alla password anche se è debole
                        string saltedPassword = password + Convert.ToBase64String(salt);
                        string encryptedPassword = EncryptString(saltedPassword, websiteUrl);

                        // Aggiungi la password al database
                        passwordDatabase[key] = new PasswordEntry
                        {
                            Username = username,
                            Password = encryptedPassword,
                            Website = websiteUrl,
                            Salt = Convert.ToBase64String(salt) // Salva il salt nel database
                        };

                        MessageBox.Show("Password has been saved", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                        LogToFile($"Added password: {websiteUrl}");
                        SaveDatabase();

                        // Torna alla pagina principale
                        ShowMainPage();
                    }
                }
            }
            else
            {
                MessageBox.Show("Username is null or pw and pw confirmation do not correspond", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ShowMainPage()
        {
            HomeScreen.Visibility = Visibility.Visible;
            AddPasswordFrame.Visibility = Visibility.Collapsed;
            DeletePasswordFrame.Visibility = Visibility.Collapsed;
            ViewArchiveFrame.Visibility = Visibility.Collapsed;
            GeneratePasswordFrame.Visibility = Visibility.Collapsed;
            ViewLogFrame.Visibility = Visibility.Collapsed;

            //clean form
            UsernameTextBox.Clear();
            PasswordBox.Clear();
            ConfirmPasswordBox.Clear();
            WebsiteTextBox.Clear();
        }
        private void Cancel_Click(object sender, RoutedEventArgs e) {

            ShowMainPage();

        }
        private void RefreshLog_Click(object sender, RoutedEventArgs e) {
            try
            {
                string logContent = File.ReadAllText(LogFileName);

                //show log interface
                LogTextBox.Text = logContent;
            }
            catch (FileNotFoundException)
            {
                
                MessageBox.Show("File not found", "Err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                // Gestisci altre eccezioni qui, ad esempio problemi di accesso al file
                MessageBox.Show($"an error has been rised during database reading: {ex.Message}", "err", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
 
            private void Refresh_Click(object sender, RoutedEventArgs e)
            {
                List<PasswordEntry> archivedPasswords = GetArchivedPasswords();
                UpdateArchiveListView(archivedPasswords);
            }
        

        private void OpenWebsite_Click(object sender, MouseButtonEventArgs e)
        {
            //footer
            string websiteUrl = "https://github.com/CodeAnarchist";
            System.Diagnostics.Process.Start(websiteUrl);
        }
        private class PasswordEntry
        {
            public string Username { get; set; }
            public string Password { get; set; }
            public string Website { get; set; }
            public string Salt { get; set; }
        }
    }
    public partial class MasterPasswordWindow : Window
    {
        public string MasterPassword { get; private set; }

        public MasterPasswordWindow()
        {
            InitializeComponent();
        }

        private void ConfirmButton_Click(object sender, RoutedEventArgs e)
        {
            //get master password
            MasterPassword = MasterPasswordBox.Password;
            Close();
        }
    }
}
