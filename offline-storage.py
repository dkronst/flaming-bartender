#!/usr/bin/env python

from gi.repository import Gtk

class FileChooserEntry(Gtk.HBox):
    def __init__(self, parent=None, title=None):
        if parent:
            self.parent = parent
        self.title = title

        Gtk.HBox.__init__(self)
        browse_button = Gtk.Button("Browse...")
        browse_button.connect("clicked", self.on_browse)

        self.file_entry = Gtk.Entry()
        self.file_entry.set_sensitive(False)

        self.pack_start(self.file_entry, True, True, 0)
        self.pack_end(browse_button, False, False, 0)

    def on_browse(self, widget):
        """
        Run a file chooser dialog
        """
        title = self.title or None
        chooser = Gtk.FileChooserDialog(title=title, action=Gtk.FileChooserAction.SAVE,
                do_overwrite_confirmation=True, buttons=(Gtk.STOCK_CANCEL,Gtk.ResponseType.CANCEL,Gtk.STOCK_OPEN,Gtk.ResponseType.OK))
        r = chooser.run()

        if r == Gtk.ResponseType.OK:
            self.file_entry.set_text(chooser.get_filename())
        chooser.destroy()

    def get_filename(self):
        return self.file_entry.get_text()
    

class BTCWindow(Gtk.Window):
    def __init__(self):
        from pyme import core
        
        core.check_version(None)

        self.c = core.Context()
        self.c.set_armor(1)

        Gtk.Window.__init__(self, title="Bitcoin Offline Storage Tool")

        self.btc_filename = None
        self.gpg_filename = None

        self.button_generate = Gtk.Button(label="Generate")
        self.button_generate.connect("clicked", self.on_button_generate_clicked)
        box1 = Gtk.Box(spacing=20)
        label1 = Gtk.Label(label="Filename to write new keys to: ", halign=Gtk.Align.END)
        label2 = Gtk.Label(label="Number of keys/addresses to generate: ", halign=Gtk.Align.END)
        label3 = Gtk.Label(label="GPG Encrypt using public keys for the following email addresses/GPG IDs: ", halign=Gtk.Align.END)
        label4 = Gtk.Label(label="Filename to write GPG keyring to (private keys included): ", halign=Gtk.Align.END)
        label5 = Gtk.Label(label="Check this box to create a new GPG key-pair (unsure? check the box as 'yes'):", halign=Gtk.Align.END)
        
        self.file_chooser_btc = FileChooserEntry(self, title="Choose a file to save encrypted bitcoin addresses")
        self.file_chooser_gpg = FileChooserEntry(self, title="Choose a file to save GPG key files")

        self.num_of_keys_spinner = Gtk.SpinButton()
        self.num_of_keys_spinner.set_adjustment(Gtk.Adjustment(1.0, 0, 1000.0, 1, 0))
        self.gpg_emails = Gtk.Entry()
        self.generate_gpg_keys = Gtk.CheckButton("Generate a new GPG key-pair")
        self.generate_gpg_keys.set_active(True)

        table = Gtk.Table(8,2,True)

        table.attach(label1, 0, 1, 0, 1)
        table.attach(self.file_chooser_btc, 1, 2, 0, 1)
        table.attach(self.num_of_keys_spinner, 1, 2, 1, 2)
        table.attach(self.button_generate, 1, 2, 7, 8)
        table.attach(label2, 0, 1, 1, 2)
        table.attach(label3, 0, 1, 2, 3)
        table.attach(self.gpg_emails, 1, 2, 2, 3)
        table.attach(label4, 0, 1, 3, 4)
        table.attach(self.file_chooser_gpg, 1, 2, 3, 4)
        table.attach(label5, 0, 1, 4, 5)
        table.attach(self.generate_gpg_keys, 1, 2, 4, 5)
        box1.add(table)
        self.add(box1)
        
    def on_button_generate_clicked(self, widget):
        self.do_generate()

    def get_gpg_keys(self):
        from pyme import core
        
        c = self.c
        ret = []

        # Set up the recipients.
        names = self.gpg_emails.get_text().split(",")
        
        for name in names:
            if not name.strip():
                continue
            c.op_keylist_start(name.strip(), 0)
            r = c.op_keylist_next()
            ret.append(r)

        return ret

    def get_user_pw(parent, message, title=''):
        # Returns user input as a string or None
        # If user does not input text it returns None, NOT AN EMPTY STRING.
        
        dialogWindow = Gtk.MessageDialog(parent,
                Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT,
                Gtk.MessageType.QUESTION,
                Gtk.ButtonsType.OK_CANCEL,
                message)
        
        
        dialogWindow.set_title(title)
        
        dialogBox = dialogWindow.get_content_area()
        userEntry = Gtk.Entry()
        userEntry.set_visibility(False)
        userEntry.set_invisible_char("*")
        userEntry.set_size_request(250,0)
        dialogBox.pack_end(userEntry, False, False, 0)
        
        dialogWindow.show_all()
        response = dialogWindow.run()
        text = userEntry.get_text() 
        dialogWindow.destroy()
        if (response == Gtk.ResponseType.OK) and (text != ''):
            return text
        else:
            raise Warning("Operation cancelled")

    def progress(*args, **kv):
        print args, kv

    def generate_gpg_key_pair(self):
        """
        Generate a key-pair for the encrypting of the BTC keys
        """
        from pyme import core, callbacks

        # Initialize our context.
        core.check_version(None)

        c = self.c

        c.set_progress_cb(self.progress, None)
        
        pass1 = self.get_user_pw("Enter password for the private key", "Key generation")
        pass2 = self.get_user_pw("Repeat password for private key", "Key generation")
        if pass1 != pass2:
            raise Warning("Passwords do not match!")
        
        dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK, "Click OK to start generating encryption key-pair.\n"+\
                "This might take a very long time...")
        dlg.run()
        dlg.destroy()

        parms = """<GnupgKeyParms format="internal">
        Key-Type: DSA
        Key-Length: 1024
        Key-Usage: sign
        Subkey-Type: ELG-E
        Subkey-Length: 1024
        Subkey-Usage: encrypt
        Name-Real: Bitcoin Key Pair
        Name-Comment: Key for the locking and unlocking of bitcoins
        Name-Email: bitcoin@localhost
        Passphrase: %s
        </GnupgKeyParms>
        """%pass1

        c.op_genkey(parms, None, None)
        fpr = c.op_genkey_result().fpr
        
        c.op_keylist_start(fpr, 0)
        key = c.op_keylist_next()
        enc_key = None

        for subkey in key.subkeys:
            keyid = subkey.keyid
            if keyid == None:
                break
            can_encrypt = subkey.can_encrypt
            if can_encrypt:
                enc_key = c.get_key(keyid, 0)
        if enc_key is None:
            print "No encryption key found!"

        return (enc_key, key)

    def generate_new_btc_keys(self):
        import addrgen
        num = self.num_of_keys_spinner.get_value()
        keys = []
        for i in range(int(num)):
            keys.append(addrgen.gen_eckey(compressed=False))

        addrs = []
        for i in keys:
            addrs.append(addrgen.get_addr(i))
            print "Added address: %s"%addrs[-1][0]

        return addrs

    def format_sec_message(self, addrs, pub_gpg_keys):
        """
        Create a GPG message (encrypted with the given public keys)
        """
        from pyme.core import Data
        from StringIO import StringIO

        c = self.c

        plain = StringIO()
        plain.write("-- SECRET - This file contains Bitcoin private keys! --\n\n")
        plain.write("Index,Address,Private Key\n")
        i = 0
        for addr, key in addrs:
            i += 1
            plain.write("%d,%s,%s\n"%(i,addr,key))

        plain_data = Data(plain.getvalue())

        cipher = Data()
        c.op_encrypt(pub_gpg_keys, 1, plain_data, cipher)
        cipher.seek(0,0)
        return cipher.read()

    def format_pub_message(self, addrs):
        """
        Format a public message with a list of addresses without their private keys attached. 
        """
        from StringIO import StringIO
        s = StringIO()

        s.write("List of addresses to be used for save Bitcoin offline storage.\n")
        s.write("Private keys are encrypted in the message below.\n")
        s.write("Whoever has this file will be only be able to know how many Bitcoins are in each address.\n")
        s.write("They will not be able to use the coins unless they have the private key and the password\n\n\n")
        s.write("Index,Address\n")

        i = 0
        for addr, pk in addrs:
            i += 1
            s.write("%d,%s\n"%(i,addr))
            
        return s.getvalue()

    def save_btc_file(self, secret_msg, public_msg):
        """
        Save BTC message to file
        """
        from os.path import isfile

        fname = self.file_chooser_btc.get_filename()

        if not fname:
            raise Warning("No file was selected for GPG output")

        if isfile(fname):
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL, 
                    "The file %s already exists. Are you sure you want to overwrite it?"%fname)
            res = dlg.run()
            dlg.destroy()
            if res != Gtk.ResponseType.OK:
                raise Warning("Operation cancelled.")

        f = open(fname, "w")
        f.write(public_msg + "\n" + secret_msg)
        f.close()

    def save_gpg_file(self, priv_gpg):
        """
        Save all secret keys - but it's easier to simply copy the whole gpg key-ring. So we'll do that for now.
        """
        from os.path import isfile
        import subprocess

        fname = self.file_chooser_gpg.get_filename()

        if not fname:
            raise Warning("No file was selected for GPG output")

        if isfile(fname):
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.QUESTION, Gtk.ButtonsType.OK_CANCEL, 
                    "The file %s already exists. Are you sure you want to overwrite it?"%fname)
            res = dlg.run()
            dlg.destroy()
            if res != Gtk.ResponseType.OK:
                raise Warning("Operation cancelled.")

        p = subprocess.Popen(["gpg", "-a", "--export-secret-keys"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        
        out, err = p.communicate()
        if(p.wait() != 0):
            raise Warning("GPG backup of secret keys failed! GPG output was: \n%s\n%s"%(out, err))

        f = open(fname, "w")
        f.write(out)
        f.close()


    def get_private_gpg_keys(self):
        """
        Returns the private gpg key used by this user
        """

        c = self.c
        return c.op_keylist_all(None, 1)

    def do_generate(self):
        try:
            if not self.file_chooser_btc.get_filename() or not self.file_chooser_gpg.get_filename():
                raise Warning("At least on output file is not specified. Make sure you specify both outputs.")
            keys = []
            keys += self.get_gpg_keys() # Gets all the public keys given in the list.
            if not self.generate_gpg_keys.get_active() and not keys:
                dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.ERROR, Gtk.ButtonsType.OK, 
                        "No public key can be found! At least one of the following must be given:\n"+\
                        "1. Generate GPG keys\n2. Specify public keys to for which to encrypt the result")
                dlg.run()
                dlg.destroy()

            if self.generate_gpg_keys.get_active():
                generated_pub_gpg, priv_gpg = self.generate_gpg_key_pair()
                keys.append(generated_pub_gpg)
            else:
                priv_gpg = self.get_private_gpg_keys()  # May have more than one...?
            
            addresses = self.generate_new_btc_keys()
            secret_msg = self.format_sec_message(addresses, keys)
            public_msg = self.format_pub_message(addresses)
            self.save_btc_file(secret_msg, public_msg)
            self.save_gpg_file(priv_gpg)
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK, "Operation completed successfully")
            dlg.run()
            dlg.destroy()
        except Warning, e:
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.ERROR, Gtk.ButtonsType.OK, "Error: %s"%e)
            dlg.run()
            dlg.destroy()


def main():
    win = BTCWindow()
    win.connect("delete-event", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__=="__main__":
    main()

