#!/usr/bin/env python

from gi.repository import Gtk

GPG_HELP_TEXT = """GPG can be used to very safely encrypt the private Bitcoin keys. 
Several recepients, for whom you have their public encryption key, may be chosen.
Always choose yourself as a recepient, otherwise you will not be able to decrypt the keys. 
This gives a 2 level security scheme that is very difficult to break even for governments.
At the end of the process you will have 2 files to save and an optional password. 
As long as you don't keep both at the similar locations, you are safe (but don't forget to keep both file very safe!)"""


class BTCWindow(Gtk.Window):
    def __init__(self):
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

        file_chooser1 = Gtk.FileChooserButton("Select Bitcoin Offline File", action=Gtk.FileChooserAction.SAVE, 
                do_overwrite_confirmation=True)
        file_chooser1.connect("file-set", self.file_selected)

        file_chooser2 = Gtk.FileChooserButton("Filename to write GPG keyring", action=Gtk.FileChooserAction.SAVE, 
                do_overwrite_confirmation=True)
        file_chooser2.connect("file-set", self.gpg_file_selected)

        self.num_of_keys_spinner = Gtk.SpinButton()
        self.num_of_keys_spinner.set_adjustment(Gtk.Adjustment(1.0, 0, 1000.0, 1, 0))
        self.gpg_emails = Gtk.Entry()
        self.generate_gpg_keys = Gtk.CheckButton("Generate a new GPG key-pair")
        self.generate_gpg_keys.set_active(True)

        table = Gtk.Table(8,2,True)

        table.attach(label1, 0, 1, 0, 1)
        table.attach(file_chooser1, 1, 2, 0, 1)
        table.attach(self.num_of_keys_spinner, 1, 2, 1, 2)
        table.attach(self.button_generate, 1, 2, 7, 8)
        table.attach(label2, 0, 1, 1, 2)
        table.attach(label3, 0, 1, 2, 3)
        table.attach(self.gpg_emails, 1, 2, 2, 3)
        table.attach(label4, 0, 1, 3, 4)
        table.attach(file_chooser2, 1, 2, 3, 4)
        table.attach(label5, 0, 1, 4, 5)
        table.attach(self.generate_gpg_keys, 1, 2, 4, 5)
        box1.add(table)
        self.add(box1)
        
    def on_button_generate_clicked(self, widget):
        self.do_generate()

    def file_selected(self, widget):
        self.btc_filename = widget.get_filename()

    def gpg_file_selected(self, widget):
        self.gpg_filename = widget.get_filename()

    def get_gpg_keys(self):
        return None

    def do_generate(self):
        keys = self.get_gpg_keys() # Gets all the public keys given in the list.
        if not self.generate_gpg_keys.get_active() and not keys:
            dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.ERROR, Gtk.ButtonsType.OK, 
                    "No public key can be found! At least one of the following must be given:\n"+\
                    "1. Generate GPG keys\n2. Specify public keys to for which to encrypt the result")
            dlg.run()
            dlg.destroy()

        if self.generate_gpg_keys.get_active():
            generated_pub_gpg, priv_gpg = self.generate_gpg_key_pair()
        else:
            priv_gpg = self.get_private_gpg_key()  # May have more than one...?
        
        addresses, priv_keys = self.generate_new_btc_keys()
        secret_msg = self.format_sec_message(priv_keys, addresses, keys)
        public_msg = self.format_pub_message(addresses)
        self.save_btc_file(secret_msg, public_msg)
        self.save_gpg_file(priv_gpg)
        dlg = Gtk.MessageDialog(self, 0, Gtk.MessageType.INFO, Gtk.ButtonsType.OK, "Operation completed successfully")
        dlg.run()
        dlg.destroy()

def main():
    win = BTCWindow()
    win.connect("delete-event", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__=="__main__":
    main()

