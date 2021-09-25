using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;


namespace W4L33Dx_JWT_BruteForce
{
    public partial class Main : Form
    {
        public Main()
        {
            InitializeComponent();
        }

        static string theResult = "Password Not Found";
        static void CheckPassword(string token, string pwd, CancellationTokenSource tokenSource)
        {

            if (!tokenSource.IsCancellationRequested)
            {

                bool result = DecodeJWT(token, pwd);
                if (result == true)
                {
                    theResult = (pwd);
                    tokenSource.Cancel();
                }
            }
        }
        public static bool DecodeJWT(string token, string key)
        {
            try
            {
                IJsonSerializer serializer = new JsonNetSerializer();
                var provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);

                var json = decoder.Decode(token, key, verify: true);
                return true;
            }
            catch (TokenExpiredException)
            {
                return false;//("Token has expired");
            }
            catch (SignatureVerificationException)
            {
                return false;// ("Token has invalid signature");
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog x = new OpenFileDialog();
            x.Filter = "*.txt|*.txt";
            x.ShowDialog();
            try
            {
                textBox1.Text = x.FileName;
                 pwdList = new List<string>(System.IO.File.ReadAllLines(textBox1.Text));
                richTextBox1.Text = ( pwdList.Count + " Password Loaded\n");
            }
            catch { }
        }
        List<string> pwdList;
        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                string theToken = textBox2.Text;
                List<Task> taskList = new List<Task>();
                CancellationTokenSource tokenSource = new CancellationTokenSource();


                foreach (string pwd in pwdList)
                {
                    Task checkTask = new Task(() => CheckPassword(theToken, pwd, tokenSource));
                    checkTask.Start();
                    taskList.Add(checkTask);
                    
                }

                Task.WaitAll(taskList.ToArray());

                
                if(theResult == ("Password Not Found"))
                {
                    richTextBox1.Text += ($"{theResult}\nDone all passwords checked");
                }
                else
                {
                    richTextBox1.Text += ($"Password : {theResult}\nDone all passwords checked");
                    IJsonSerializer serializer = new JsonNetSerializer();
                    var provider = new UtcDateTimeProvider();
                    IJwtValidator validator = new JwtValidator(serializer, provider);
                    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                    IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
                    richTextBox2.Text= decoder.Decode(textBox2.Text, theResult, verify: true);
                }
            }
            catch { }

        }
    }
}
