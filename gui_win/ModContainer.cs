/*
*    Open Patcher - A penetration testing and reverse engineering tool for applications
*    Copyright (C) 2013  Dennis Shtatnov
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;
using System.Xml;
using System.Diagnostics;

namespace open_patcher_gui_win
{
    public class ModContainer : TabPage
    {
        private string ConfigFile;
        private string File;
        private XmlDocument ConfigXml = new XmlDocument();
        private CheatContainer[] Cheats;
        public Button btnPatch = new Button();
        public CheckBox VerboseBox = new CheckBox();
        public ModContainer(string config, string file)
        {
            this.ConfigFile = config;
            this.File = file;

            //this.tabPage2.Location = new System.Drawing.Point(4, 25);
            //this.Name = "tabPage2";
            //this.tabPage2.Size = new System.Drawing.Size(879, 458);
            //this.tabPage2.TabIndex = 1;
            this.UseVisualStyleBackColor = true;
            

            ConfigXml.Load(this.ConfigFile);

            this.Text = ConfigXml.GetElementsByTagName("title")[0].InnerText;

            XmlNodeList nl = ConfigXml.GetElementsByTagName("mod");

            Cheats = new CheatContainer[nl.Count];

            int y = 10;
            for (int x = 0; x < nl.Count; x++)
            {
                Cheats[x] = new CheatContainer(nl[x]);
                this.Controls.Add(Cheats[x]);

                Cheats[x].Location = new System.Drawing.Point(10, y);
                y += Cheats[x].Size.Height + 10;
            }

            btnPatch.Text = "Patch!";
            //btnPatch.AutoSize = true;
            btnPatch.Size = new System.Drawing.Size(50, 30);
            btnPatch.Anchor = ((System.Windows.Forms.AnchorStyles)
                ((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));

            btnPatch.Location = new System.Drawing.Point(this.Size.Width - (10 + btnPatch.Size.Width), this.Size.Height - (10 + btnPatch.Size.Height));
            btnPatch.Click += new EventHandler(btnPatch_Click);
            this.Controls.Add(btnPatch);


            VerboseBox.Text = "Verbose Output";
            VerboseBox.Anchor = ((System.Windows.Forms.AnchorStyles)
                ((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            VerboseBox.AutoSize = true;

            VerboseBox.Location = new System.Drawing.Point(btnPatch.Location.X - (10 + VerboseBox.Size.Width), btnPatch.Location.Y);
            this.Controls.Add(VerboseBox);
        }

        private static bool Running = false;

        private void btnPatch_Click(object sender, EventArgs e)
        {
            if (Running)
            {
                return;
            }
            Running = true;

            string cmd = "-c=\"" + this.ConfigFile + "\" -f=\"" + this.File + "\"";
            if (VerboseBox.Checked)
            {
                cmd += " -v";
            }

            foreach (CheatContainer c in Cheats)
            {
                cmd += c.GetCmdComponent();
            }

            Form1.txtLog.Text = "Command: op.exe " + cmd + "\r\n";
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.FileName = "op";
            p.StartInfo.Arguments = cmd;
            p.OutputDataReceived += new DataReceivedEventHandler(
                (s, ev) =>
                {
                    if (ev.Data != null)
                        this.EndInvoke(this.BeginInvoke(new MethodInvoker(delegate() { Form1.txtLog.AppendText(ev.Data + "\r\n"); })));
                    else
                        Running = false;
                }
            );

            p.Exited += new EventHandler(
                (s, ev) =>
                {
                    Running = false;
                }
            );

            p.Start();
            p.BeginOutputReadLine();

        }


        public class CheatContainer : Panel
        {
            public string Key = "";
            public CheckBox EnableBox = new CheckBox();
            public Dictionary<String, String> Variables = new Dictionary<string, string>();
            public TextBox[] Inputs = new TextBox[0];
            public CheatContainer(XmlNode mod)
            {
                this.Key = mod.Attributes["key"].InnerText;

                EnableBox.AutoSize = true;
                EnableBox.Text = mod.FirstChild.InnerText;
                EnableBox.Location = new System.Drawing.Point(0, 0);
                EnableBox.Checked = true;
                EnableBox.CheckedChanged += new EventHandler(EnableBox_CheckedChanged);

                this.Controls.Add(EnableBox);

                /* TODO: Dynamic width */
                int x = 500;
                int y = 25;

                List<TextBox> boxes = new List<TextBox>();
                foreach (XmlNode n in mod.ChildNodes)
                {
                    if (n.Name == "var")
                    {
                        String key = n.Attributes["sym"].InnerText;
                        String name = n.Attributes["name"].InnerText;
                        String deflt = n.Attributes["default"].InnerText;

                        Variables.Add(key, deflt);


                        Label l = new Label();
                        l.Text = name;
                        l.AutoSize = true;
                        l.Location = new System.Drawing.Point(40, y);
                        this.Controls.Add(l);

                        TextBox t = new TextBox();
                        t.Size = new System.Drawing.Size(200, 22);
                        t.Text = Variables[key];
                        t.Location = new System.Drawing.Point(50 + l.Size.Width, y);
                        y += 10 + t.Size.Height;

                        t.TextChanged += new EventHandler(varBox_TextChanged);
                        t.Name = key;

                        this.Controls.Add(t);
                        boxes.Add(t);

                    }
                }

                Inputs = boxes.ToArray();

                this.Size = new System.Drawing.Size(x, y);
                //this.BackColor = System.Drawing.Color.Aqua;
                //this.TabIndex = 4;

            }

            private void EnableBox_CheckedChanged(object sender, EventArgs e)
            {
                bool ro = !((CheckBox)sender).Checked;
                for (int x = 0; x < Inputs.Length; x++)
                {
                    Inputs[x].ReadOnly = ro;
                }
            }

            private void varBox_TextChanged(object sender, EventArgs e)
            {
                TextBox t = (TextBox)sender;
                Variables[t.Name] = t.Text;
            }

            public string GetCmdComponent()
            {
                if (!EnableBox.Checked)
                {
                    return "";
                }

                string cmd = " --" + Key;
                foreach (String key in Variables.Keys)
                {
                    cmd += " -" + key + "=\"" + Variables[key] + "\"";
                }

                return cmd;
            }
        }

    }
}
