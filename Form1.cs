using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using Dotwall_deobfuscator.Decryptor;

namespace StringDLLProtection
{
    public partial class Form1 : Form
    {
        #region Declarations

        public string DirectoryName = "";
        public int ConstantKey;
        public int ConstantNum;
        public MethodDef Methoddecryption;
        public TypeDef Typedecryption;
        public MethodDef MethodDemo;
        public ModuleDefMD module;
        public int x;
        public int DeobedStringNumber;
        public static string resourcename { get; set; }
        public static string filename { get; set; }


        #endregion

        #region Designer

        public Form1()
        {
            InitializeComponent();
        }

        private void TextBox1DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Copy;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void TextBox1DragDrop(object sender, DragEventArgs e)
        {
            try
            {
                Array array = (Array)e.Data.GetData(DataFormats.FileDrop);
                if (array != null)
                {
                    string text = array.GetValue(0).ToString();
                    int num = text.LastIndexOf(".", StringComparison.Ordinal);
                    if (num != -1)
                    {
                        string text2 = text.Substring(num);
                        text2 = text2.ToLower();
                        if (text2 == ".exe" || text2 == ".dll")
                        {
                            Activate();
                            textBox1.Text = text;
                            int num2 = text.LastIndexOf("\\", StringComparison.Ordinal);
                            if (num2 != -1)
                            {
                                DirectoryName = text.Remove(num2, text.Length - num2);
                            }
                            if (DirectoryName.Length == 2)
                            {
                                DirectoryName += "\\";
                            }
                        }
                    }
                }
            }
            catch
            {
            }
        }
        private void button3_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            label2.Text = "";
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Title = "Browse for target assembly";
            openFileDialog.InitialDirectory = "c:\\";
            if (DirectoryName != "")
            {
                openFileDialog.InitialDirectory = this.DirectoryName;
            }
            openFileDialog.Filter = "All files (*.exe,*.dll)|*.exe;*.dll";
            openFileDialog.FilterIndex = 2;
            openFileDialog.RestoreDirectory = true;
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string fileName = openFileDialog.FileName;
                textBox1.Text = fileName;
                int num = fileName.LastIndexOf("\\", StringComparison.Ordinal);
                if (num != -1)
                {
                    DirectoryName = fileName.Remove(num, fileName.Length - num);
                }
                if (DirectoryName.Length == 2)
                {
                    DirectoryName += "\\";
                }
            }
        }
        #endregion

        private void button2_Click(object sender, EventArgs e)
        {
            ModuleDefMD module = ModuleDefMD.Load(textBox1.Text);
            CheckResource(module);
            if (resourcename == null)
            {
                return;
            }
            GetDecryptionMethod(module);
            GetDecryptionCall(module, Typedecryption);
            string text2 = Path.GetDirectoryName(textBox1.Text);
            if (!text2.EndsWith("\\"))
            {
                text2 += "\\";
            }
            string path = text2 + Path.GetFileNameWithoutExtension(textBox1.Text) + "_patched" +
                          Path.GetExtension(textBox1.Text);
            var opts = new ModuleWriterOptions(module);
            opts.Logger = DummyLogger.NoThrowInstance;
            module.Write(path, opts);
            label2.Text = "Successfully decrypted " + DeobedStringNumber + " strings !";
        }

        private void GetDecryptionCall(ModuleDef Module, TypeDef typedecryption)
        {
            resourcename = textBox2.Text;
            filename = textBox1.Text;
            foreach (TypeDef type in Module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == null)
                        continue;
                    CilBody body = method.Body;
                    body.SimplifyBranches();
                    int x = 0;
                    while (x < body.Instructions.Count)
                    {
                        if (body.Instructions[x].OpCode == OpCodes.Call)
                        {
                            if (body.Instructions[x].Operand.ToString().ToLower().Contains(typedecryption.ToString().ToLower()))
                            {
                                try
                                {
                                    var num1 = body.Instructions[x - 3].Operand.ToString();
                                    int a = int.Parse(num1);
                                    int num2 = 1;
                                    num2 = num2 + a;
                                    var parameterint = num2;
                                    string z = decrypt.decryptor(parameterint, resourcename, filename);

                                    body.Instructions[x].OpCode = OpCodes.Ldstr;
                                    body.Instructions[x].Operand = z;
                                    body.Instructions.RemoveAt(x - 1);
                                    body.Instructions.RemoveAt(x - 2);
                                    body.Instructions.RemoveAt(x - 3);
                                    DeobedStringNumber = DeobedStringNumber + 1;
                                    x++;
                                }
                                catch (Exception e)
                                {
                                    //MessageBox.Show(e.ToString());
                                    x++;
                                }
                                
                            }
                        }
                        x++;
                    }
                }
            }
        }

        private void GetDecryptionMethod(ModuleDef Module)
        {
            foreach (TypeDef type in Module.Types)
            {
                foreach (MethodDef method in type.Methods)
                {
                    if (method.HasBody == null)
                        continue;
                    if (method.IsConstructor == false)
                        continue;
                        CilBody body = method.Body;
                        body.SimplifyBranches();
                        var x = 0;

                        while (x < body.Instructions.Count)
                        {
                            if (body.Instructions[x].OpCode == OpCodes.Call)
                            {
                                if (body.Instructions[x].Operand.ToString().ToLower().Contains("system.reflection.assembly::getexecutingassembly"))
                                {
                                    Typedecryption = method.DeclaringType;
                                    richTextBox1.AppendText("Decryption type : " + Typedecryption + Environment.NewLine);
                                    foreach (MethodDef methoda in type.Methods)
                                    {
                                        if (methoda.IsConstructor)
                                            continue;
                                        if (methoda.Body.Instructions.Count > 5)
                                            continue;
                                        int xy = 0;
                                        while (xy < methoda.Body.Instructions.Count)
                                        {
                                            if (methoda.Body.Instructions[xy].OpCode == OpCodes.Call)
                                            {
                                                if (methoda.Body.Instructions[xy].Operand == null)
                                                {
                                                    xy++;
                                                    continue;
                                                }
                                                if (!methoda.Body.Instructions[xy].Operand.ToString().Contains("object"))
                                                {
                                                    Methoddecryption = methoda;
                                                    break;
                                                }
                                            }
                                            else
                                                xy++;
                                        }
                                    }
                                }
                            }
                            x++;
                        }
                        x++;

                    
                }
            }
        }

        private void CheckResource(ModuleDef Module)
        {
            if (Module.Resources.Count == 1)
            {
                label2.ForeColor = Color.Crimson;
                label2.Text = "Please first unpack resources !";
                return;
            }
            foreach (Resource res in Module.Resources)
            {
                if (res.Name.Contains("."))
                    continue;

                resourcename = res.Name;
                textBox2.Text = res.Name;
            }
        }

    }

}
