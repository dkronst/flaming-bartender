#!/usr/bin/env python

from gi.repository import Gtk

GPG_HELP_TEXT = """GPG can be used to very safely encrypt the private Bitcoin keys. 
Several recepients, for whom you have their public encryption key, may be chosen.
Always choose yourself as a recepient, otherwise you will not be able to decrypt the keys. 
This gives a 2 level security scheme that is very difficult to break even for governments.
At the end of the process you will have 2 files to save and an optional password. 
As long as you don't keep both at the similar locations, you are safe (but don't forget to keep both file very safe!)"""


class MyWindow(Gtk.Window):
    def __init__(self):
        Gtk.Window.__init__(self, title="Bitcoin Offline Storage Tool")
        self.button_generate = Gtk.Button(label="Generate")
        self.button_generate.connect("clicked", self.on_button_generate_clicked)
        box1 = Gtk.Box(spacing=20)
        label1 = Gtk.Label(label="Filename to write new keys to: ", halign=Gtk.Align.END)
        label2 = Gtk.Label(label="Number of keys/addresses to generate: ", halign=Gtk.Align.END)
        label3 = Gtk.Label(label="GPG Encrypt using public keys for the following email addresses: ", halign=Gtk.Align.END)
        label4 = Gtk.Label(label="Filename to write GPG keyring to (private keys included): ", halign=Gtk.Align.END)
        file_chooser1 = Gtk.FileChooserButton("Select Bitcoin Offline File", action=Gtk.FileChooserAction.SAVE, 
                do_overwrite_confirmation=True)
        file_chooser1.connect("file-set", self.file_selected)
        self.num_of_keys_spinner = Gtk.SpinButton()
        self.num_of_keys_spinner.set_adjustment(Gtk.Adjustment(0.0, 0, 1000.0, 1, 0))

        table = Gtk.Table(8,3,True)

        table.attach(label1, 0, 1, 0, 1)
        table.attach(file_chooser1, 1, 2, 0, 1)
        table.attach(self.num_of_keys_spinner, 1, 2, 1, 2)
        table.attach(self.button_generate, 1, 2, 7, 8)
        table.attach(label2, 0, 1, 1, 2)
        table.attach(label3, 0, 1, 2, 3)
        box1.add(table)
        self.add(box1)
        
    def on_button_generate_clicked(self, widget):
        print "Generating..."

    def file_selected(self, widget):
        self.btc_filename = widget.get_filename()

def main():
    win = MyWindow()
    win.connect("delete-event", Gtk.main_quit)
    win.show_all()
    Gtk.main()

if __name__=="__main__":
    main()

