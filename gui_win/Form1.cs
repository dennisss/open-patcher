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
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Xml;

namespace open_patcher_gui_win
{
    public partial class Form1 : Form
    {
        public ModContainer Container = null;
        public void Load(string config, string file)
        {
            Container = new ModContainer(config, file);

            this.tabControl1.Controls.Add(Container);
        }


        public Form1()
        {
            //TODO: Move the designer code for txtLog here
            InitializeComponent();
        }

        //Open Folder
        private void openFileToolStripMenuItem_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog d = new FolderBrowserDialog();
            d.ShowDialog();

            string[] files = Directory.GetFiles(d.SelectedPath);
            string[] configs = Directory.GetFiles("config", "*.xml");

            bool found = false;
            string config = "";
            string file = "";


            foreach (string c in configs)
            {
                XmlDocument xml = new XmlDocument();
                xml.Load(c);

                XmlNode info = xml.GetElementsByTagName("info")[0];
                XmlNodeList acceptedBins = xml.GetElementsByTagName("bin");
                foreach (XmlNode n in acceptedBins)
                {
                    foreach(string f in files){
                        if(Path.GetFileName(f) == n.InnerText){
                            found = true;
                            config = c;
                            file = f;
                            break;
                        }
                    }

                    if (found)
                        break;
                }

                if (found)
                    break;
            }

            if (found)
            {
                Load(config, file);
            }
            else
            {
                MessageBox.Show("No file could be matched to a mod file. Make sure that the you did not change the name of the original executable.");
            }




        }

        //Open File
        private void openFileToolStripMenuItem1_Click(object sender, EventArgs e)
        {
            OpenFileDialog d = new OpenFileDialog();
            d.ShowDialog();

            if (File.Exists(d.FileName))
            {
                MessageBox.Show("Please Select a Configuration File");
                OpenFileDialog d2 = new OpenFileDialog();
                d2.Filter = "Config file (.xml)|*.xml";
                d2.InitialDirectory = System.Environment.CurrentDirectory + "\\config\\";
                d2.ShowDialog();

                if (File.Exists(d2.FileName))
                {
                    Load(d2.FileName, d.FileName);
                }
            }

        }

    }
}
