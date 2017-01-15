#
# Loxodo -- Password Safe V3 compatible Password Vault
# Copyright (C) 2008 Christoph Sommer <mail@christoph-sommer.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import os
import sys
from optparse import OptionParser
import getpass
import readline
import cmd
import re
import time
import csv
try:
    import pygtk
    import gtk
except ImportError:
    pygtk = None
    gtk = None

from ...vault import Vault
from ...config import config

class InteractiveConsole(cmd.Cmd):

    def __init__(self):
        self.vault = None
        self.vault_file_name = None
        self.vault_password = None
        self.vault_modified = False
        self.vault_status = ""

        self.vi = False
        self.tabcomp = True
        self.echo = False
        self.mod = False
        # options for sorting are 'alpha' and 'mod'
        self.sort_key = 'alpha'
        self.verbose = False

        cmd.Cmd.__init__(self)
        if sys.platform == "darwin":
            readline.parse_and_bind('bind ^I rl_complete')
        self.intro = 'Ready for commands. Type "help" or "help <command>" for help, type "quit" to quit.'
        self.prompt = "[none]> "

    def create_vault(self):
        if os.path.isfile(self.vault_file_name):
            print "Overwriting %s ..." % self.vault_file_name
            try:
                answer = getpass.getpass("Continue? [y/N] >")
                if answer.lower() != "y":
                    print " exit requested... exiting."
                    sys.exit(0)
            except (KeyboardInterrupt, EOFError):
                print " exit requested... exiting."
                sys.exit(0)
        else:
            print "Creating %s ..." % self.vault_file_name

        self.vault_password = self.get_vault_password(require_confirmation=True)
        self.vault_modified = True

        if os.path.isfile(self.vault_file_name):
            Vault.create(self.vault_password, filename=self.vault_file_name)
        self.vault = Vault(self.vault_password, filename=self.vault_file_name)
        print "... Done.\n"

    def set_prompt(self):
        if self.vault_modified:
            self.vault_status = "*"
        else:
            self.vault_status = ""
        self.prompt = "[%s%s]> " % (os.path.basename(self.vault_file_name), self.vault_status)

    def get_vault_password(self, require_confirmation=False, allow_empty=False):
        try:
            while True:
                vault_password = getpass.getpass("Vault password: ")
                if vault_password == "" and not allow_empty:
                    raise EOFError
                if not require_confirmation:
                    return vault_password
                vault_password_confirmation = getpass.getpass("Re-type the password: ")
                if vault_password == vault_password_confirmation:
                    return vault_password
                else:
                    print "Passwords do not match... try again.\n"
        except EOFError:
            print "No password given\n\nBye."
            raise RuntimeError("No password given")

    def open_vault(self):
        creating_vault = False
        vault_action = "Opening"

        if not os.path.isfile(self.vault_file_name):
            creating_vault = True
            vault_action = "Creating"

        print "%s %s ..." % (vault_action, self.vault_file_name)
        self.vault_password = self.get_vault_password(require_confirmation=creating_vault)
        if creating_vault:
            self.vault_modified = True

        try:
            self.vault = Vault(self.vault_password, filename=self.vault_file_name)
        except Vault.BadPasswordError:
            print "Bad password."
            raise
        except Vault.VaultVersionError:
            print "This is not a PasswordSafe V3 vault."
            raise
        except Vault.VaultFormatError:
            print "Vault integrity check failed."
            raise
        print "... Done.\n"

    def postloop(self):
        print

    def postcmd(self, stop, line):
        if stop == True:
            return True

        self.set_prompt()

    def emptyline(self):
        pass

    def do_help(self, line):
        """
        Displays the help message.
        """
        if line:
            cmd.Cmd.do_help(self, line)
            return

        print "\nCommands:"
        print "  ".join(("ls/search",
                         "show",
                         "add",
                         "mod",
                         "del",
                         "save",
                         "export",
                         "import",
                         "quit",
                         ))
        print "\nMode switches:"
        print "  ".join((
                         "echo",
                         "uuid",
                         "sort",
                         "vi",
                         "tab",
                         "verbose",
                         ))
        print
        print "Modes:"
        print "echo passwords is %s" % self.echo
        print "uuid mode is %s" % self.uuid
        print "sort criteria is %s" % self.sort_key
        print "vi editing mode is %s" % self.vi
        print "tab completion is %s" % self.tabcomp
        print "verbose mode is %s" % self.verbose
        print

    # This method should clear all data in self.vault.records because we
    # can't control when will this be Garbadge collected we replace it
    # for strange text
    def clear_vault(self):
        self.vault.clear_records()

    def do_quit(self, line):
        """
        Saves the vault contents and exits interactive mode.
        """
        self.do_save()
        self.clear_vault()
        return True

    def do_save(self, line=None):
        """
        Save the vault without exiting.
        """
        self.check_vault()

        if self.vault_modified and self.vault_file_name and self.vault_password:
            self.vault.write_to_file(self.vault_file_name, self.vault_password)
            self.vault_modified = False
            print "Changes Saved"

    def do_EOF(self, line):
        """
        Exits interactive mode.
        """
        if self.vault_modified:
            print " pressed... changes were not saved!"
        else:
            print " pressed... exiting."
        return True

    def do_add(self, line=None):
        """
        Adds an entry to the vault.
        """
        self.check_vault()

        entry = self.vault.Record.create()
        try:
            while True:
                entry.title = getpass._raw_input('Entry\'s title: ')
                if entry.title == "":
                    accept_empty = getpass._raw_input("Entry is empty. Enter Y to accept ")
                    if accept_empty.lower() == 'y':
                        break
                else:
                    break
            entry.group = getpass._raw_input('Entry\'s group: ')
            entry.user = getpass._raw_input('Username: ')
            entry.notes = getpass._raw_input('Entry\'s notes: ')
            entry.url = getpass._raw_input('Entry\'s url: ')
            entry.passwd = self.prompt_password()
        except EOFError:
            print ""
            return

        self.vault.records.append(entry)
        self.vault_modified = True
        print "Entry Added, but vault not yet saved"
        self.set_prompt()

    def do_export(self, line=None):
        """
        Dumps a comma-separated content of the records.
        """
        # TODO(climent): create a file and write the contents.
        print "Exporting vault file %s ..." % self.vault_file_name
        self.vault.export(self.vault_password, self.vault_file_name)

    def generate_password(self):
        from src.random_password import random_password as rp
        # TODO(climent): move the options to the config file

        def print_policy(policy):
            for i in policy:
                print '%s: %s' % (policy[i][0], policy[i][1])

        policy = {
            'L': ['[L]efthand', True],
            'R': ['[R]ighthand', True],
            'U': ['[U]ppercase', True],
            'l': ['[l]owercase', True],
            'N': ['[N]umbers', True],
            'S': ['[S]ymbols', True],
            's': ['[s]imple symbols', True]
            }

        response = None
        while True:
            if not response:
                passwd = rp().generate_password(password_policy=policy, pwlength=config.pwlength)
                print "Generated password: %s" % passwd
            response = getpass._raw_input('Accept [y/./ENTER] > ')
            if response in policy:
                policy[response][1] = not policy[response][1]
                print_policy(policy)
                continue
            if response == ".":
                print_policy(policy)
            if response.lower() == "y":
                return passwd

    def prompt_password(self, old_password=None):
        message = "Type new password. [.] for none, [ENTER] for random."
        if old_password:
            message = "Type new password. [.] for none, [..] to keep the same, [ENTER] for random."

        while True:
            try:
                passwd = getpass.getpass("%s\nPassword: " % message)
            except EOFError:
                raise
            if not passwd:
                return self.generate_password()
            if old_password and passwd == "..":
                return old_password
            if passwd == '.':
                passwd2 = getpass.getpass("Enter y to accept an empty password or \".\" to use a period as a password.")
                if passwd2.lower() == "y":
                    return ""
                if passwd2 == ".":
                    return "."
                continue
            if getpass.getpass("Re-Type Password: ") == passwd:
                return passwd
            else:
                print "Passwords don't match!!"

    def do_del(self, line=None):
        """
        Delete an entry from the vault.

        Entries can only be deleted using the UUID.
        """
        self.check_vault()

        try:
            match_records, nonmatch_records = self.find_matches(line)
        except:
            return

        if not match_records:
            print "No matches found."
            return

        if len(match_records) > 1:
            print "Too many records matched your search criteria"
            for record in match_records:
                print "[%s.%s] <%s>" % (record.group.encode('utf-8', 'replace'),
                                      record.title.encode('utf-8', 'replace'),
                                      record.user.encode('utf-8', 'replace'))
            return

        if len(match_records) == 1:
            print "Deleting the following record:"
            self.do_show(str(match_records[0].uuid), hide_password=True)
            try:
                confirm_delete = getpass._raw_input("Confirm you want to delete the record by writing \"yes\": ")
            except EOFError, KeyboardInterrupt:
                print "\nDelete cancelled..."
                return
            if confirm_delete.lower() == 'yes':
                self.vault.records = nonmatch_records
                print "Entry Deleted, but vault not yet saved"
                self.vault_modified = True

        print ""

    def check_vault(self):
        if not self.vault:
            raise RuntimeError("No vault opened")

    def do_mod(self, line=None):
        """
        Modify an entry from the vault.
        """
        self.check_vault()

        try:
            match_records, nonmatch_records = self.find_matches(line)
        except:
            return

        if not match_records:
            print "No matches found."
            return

        if len(match_records) > 1:
            print "Too many records matched your search criteria."
            if line:
                for record in match_records:
                    print "[%s.%s] [%s]" % (record.group.encode('utf-8', 'replace'),
                                          record.title.encode('utf-8', 'replace'),
                                          record.user.encode('utf-8', 'replace'))
            return

        vault_modified = False
        record = match_records[0]
        new_record = {}

        print ''
        if self.uuid is True:
            print 'Uuid: [%s]' % str(record.uuid)
        print 'Modifying: [%s.%s]' % (record.group.encode('utf-8', 'replace'), record.title.encode('utf-8', 'replace'))
        print 'Enter a single dot (.) to clear the field, ^D to maintain the current entry.'
        print ''

        try:
            new_record['group'] = getpass._raw_input('Group [%s]: ' % record.group)
        except EOFError:
            new_record['group'] = ""
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['group'] == ".":
            new_record['group'] = ""
        elif new_record['group'] == "":
            new_record['group'] = record.group
        if new_record['group'] != record.group:
            vault_modified = True

        try:
            new_record['title'] = getpass._raw_input('Title [%s]: ' % record.title)
        except EOFError:
            new_record['title'] = ""
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['title'] == ".":
            new_record['title'] = ""
        elif new_record['title'] == "":
            new_record['title'] = record.title
        if new_record['title'] != record.title:
            vault_modified = True

        try:
            new_record['user'] = getpass._raw_input('User  [%s]: ' % record.user)
        except EOFError:
            new_record['user'] = ""
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['user'] == ".":
            new_record['user'] = ""
        elif new_record['user'] == "":
            new_record['user'] = record.user
        if new_record['user'] != record.user:
            vault_modified = True

        try:
            new_record['password'] = self.prompt_password(old_password=record.passwd)
        except EOFError:
            new_record['password'] = record.passwd
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['password'] != record.passwd:
            vault_modified = True

        if record.notes.encode('utf-8', 'replace') != "":
            print '[NOTES]'
            print '%s' % record.notes

        try:
            new_record['notes'] = getpass._raw_input('Entry\'s notes: ')
        except EOFError:
            new_record['notes'] = ""
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['notes'] == ".":
            new_record['notes'] = ""
        elif new_record['notes'] == "":
            new_record['notes'] = record.notes
        if new_record['notes'] != record.notes:
            vault_modified = True

        try:
            new_record['url'] = getpass._raw_input('Entry\'s url [%s]: ' % record.url)
        except EOFError:
            new_record['url'] = ""
            print ""
        except KeyboardInterrupt:
            print " pressed. Aborting modifications."
            return

        if new_record['url'] == ".":
            new_record['url'] = ""
        elif new_record['url'] == "":
            new_record['url'] = record.url
        if new_record['url'] != record.url:
            vault_modified = True

        if vault_modified == True:
            record.title = new_record['title']
            record.user = new_record['user']
            record.group = new_record['group']
            record.notes = new_record['notes']
            record.url = new_record['url']
            record.passwd = new_record['password']

            self.vault.records = nonmatch_records
            self.vault.records.append(record)
            print "Entry Modified, but vault not yet saved"
            self.vault_modified = True

        print ""

    def do_import(self, line=None):
        """
        Adds a CSV importer, based on CSV file

        Example: /home/user/data.csv
        Columns: uuid,Group,Title,User,Password,Notes,URL
        """
        self.check_vault()

        if not line:
            cmd.Cmd.do_help(self, "import")
            return

        data = csv.reader(open(line, 'rb'))
        try:
            for row in data:
                entry = self.vault.Record.create()
                entry.group = row[1]
                entry.title = row[2]
                entry.user = row[3]
                entry.passwd = row[4]
                entry.notes = row[5]
                entry.url = row[6]
                self.vault.records.append(entry)
                if self.verbose:
                    print "Added entry %s to the database." % row[0]
            self.vault_modified = True
            print "Import completed, but not saved."
        except (AttributeError, IndexError, csv.Error) as e:
            print 'file %s, line %d: %s' % (line, data.line_num, e)

    def do_search(self, line=None):
        self.do_ls(line)

    def do_ls(self, line=None):
        """
        Show contents of this vault.
        
        If an argument is passed it is treated as a regular expression and a
        case insensitive search of the fields is done.
        """
        self.check_vault()

        if line:
            try:
                vault_records = self.find_titles(line)
            except:
                return
            if not vault_records:
                print "No matches found for \"%s\"." % line
                return
        else:
            vault_records = self.vault.records[:]
            if not vault_records:
                print "No records found."
                return

        vault_records, _ = self.sort_matches(vault_records)

        print ""
        print "[group.title] username"
        if self.verbose:
            print "    URL: url"
            print "    Notes: notes"
            print "    Last mod: modification time"
        print "-"*10
        for record in vault_records:
            print "[%s.%s] %s" % (record.group.encode('utf-8', 'replace'),
                                   record.title.encode('utf-8', 'replace'),
                                   record.user.encode('utf-8', 'replace'))
            if self.verbose:
                if record.url:
                    print "    URL: %s" % (record.url.encode('utf-8', 'replace'))
                if record.notes:
                    print "    Notes: %s" % (record.notes.encode('utf-8', 'replace'))
                if record.last_mod != 0:
                    print "    Last mod: %s" % time.strftime('%Y/%m/%d',time.gmtime(record.last_mod))

        print ""

    def sort_matches(self, matches, nonmatches=None):
        lambda_alpha = lambda e1, e2: cmp(".".join([e1.group, e1.title]), ".".join([e2.group, e2.title]))
        lambda_mod = lambda e1, e2: cmp(e1.last_mod, e2.last_mod)
        if not nonmatches:
            nonmatches = []
        if self.sort_key == 'alpha':
            matches.sort(lambda_alpha)
            nonmatches.sort(lambda_alpha)
        elif self.sort_key == 'mod':
            matches.sort(lambda_mod)
            nonmatches.sort(lambda_mod)
        return matches, nonmatches

    def do_output(self, line=None):
        """
        Change status of output
        """
        if self.output == 'brief':
            self.output = 'verbose'
        else:
            self.output = 'brief'
        print "output is %s" % self.output

    def do_sort(self, line=None):
        """
        Change status of sort key
        """
        if self.sort_key == 'alpha':
            self.sort_key = 'mod'
        else:
            self.sort_key = 'alpha'
        print "sort key is %s" % self.sort_key

    def do_uuid(self, line=None):
        """
        Change status of the uuid setting.

        If True, shows the UUID of the vault entries when showing the output.
        """
        self.uuid = not self.uuid
        print "uuid is %s" % self.uuid

    def do_echo(self, line=None):
        """
        Change status of the echo setting.

        If False, hide the password field when showing the output.
        """
        self.echo = not self.echo
        print "echo is %s" % self.echo

    def do_vi(self, line=None):
        """
        Set vi editing mode for commandline
        """
        if self.vi == False:
            readline.parse_and_bind('set editing-mode vi')
        else:
            readline.parse_and_bind('set editing-mode emacs')
        self.vi = not self.vi
        print "Vi Editing mode is %s" % self.vi

    def do_verbose(self, line=None):
        """
        Enable verbose listing of vault entries
        """
        self.verbose = not self.verbose
        print "Verbose listing mode is %s" % self.verbose

    def do_tab(self, line=None):
        """
        Enable Tab completion for cmd interface
        """
        if self.tabcomp == False:
            readline.parse_and_bind('tab: complete')
        else:
            readline.parse_and_bind('tab: noncomplete')
        self.tabcomp = not self.tabcomp

        print "TAB completion mode is %s" % self.tabcomp

    def do_show(self, line, do_echo=True, hide_password=False):
        """
        Show the specified entry (including its password).

        A case insenstive search of titles is done, entries can also be
        specified as regular expressions.
        """
        self.check_vault()

        try:
            matches = self.find_titles(line)
            if not matches:
                print "No entry found for \"%s\"." % line
                return
        except:
            return

        print ""
        for record in matches:
            if self.uuid:
                print "[%s]" % record.uuid
            print ("[%s.%s]\nUsername : %s""" %
                (record.group.encode('utf-8', 'replace'),
                 record.title.encode('utf-8', 'replace'),
                 record.user.encode('utf-8', 'replace')))

            if self.echo or do_echo:
                if not hide_password:
                    print "Password : %s" % record.passwd.encode('utf-8', 'replace')

            if record.notes.strip():
                print "Notes    : %s" % record.notes.encode('utf-8', 'replace')

            if record.url:
                print "URL      : %s" % record.url.encode('utf-8', 'replace')

            if record.last_mod != 0:
                print "Last mod : %s" % time.strftime('%Y/%m/%d', time.gmtime(record.last_mod))

            print ""

            if pygtk is not None and gtk is not None:
                cb = gtk.clipboard_get()
                if cb is not None:
                  cb.set_text(record.passwd)
                  cb.store()

    def complete_show(self, text, line, begidx, endidx):
        if not text:
            completions = [record.title for record in self.vault.records]
        else:
            fulltext = line[5:]
            lastspace = fulltext.rfind(' ')
            if lastspace == -1:
                completions = [record.title for record in self.vault.records if
                    record.title.upper().startswith(text.upper())]
            else:
                completions = [record.title[lastspace+1:] for record in
                    self.vault.records if
                    record.title.upper().startswith(fulltext.upper())]

        completions.sort(lambda e1, e2: cmp(e1.title, e2.title))
        return completions


    def find_matches(self, line=None):
        """Finds matching records.

        This methos finds matching records by uuid, or any combination of
        group, title and user, case insensitive.

        The search for matches starts very narrow and widens:
        1. use uuid
        2. combine group.title.username and check for a match
        3. combine group.title
        4. combine title.username
        5. check in any of the fields
        """
        self.check_vault()

        matches = []
        nonmatches = []

        uuid = None
        title = None
        user = None
        group = None

        uuid_regexp = '^[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$'
        pattern = re.compile(uuid_regexp, re.IGNORECASE)

        if pattern.match(line):
            matches = []
            nonmatches = []
            # be agressive with the UUID matching
            for record in self.vault.records:
                if str(record.uuid) == line:
                    matches.append(record)
                else:
                    nonmatches.append(record)
            return self.sort_matches(matches, nonmatches)

        try:
            pattern = re.compile(line, re.IGNORECASE)
        except:
            print "Invalid regexp: %s" % line
            raise

        for sep in ".", " ":
            matches = []
            nonmatches = []
            for record in self.vault.records:
                if pattern.match('%s%s%s%s%s' % (record.group, sep, record.title, sep, record.user)):
                    matches.append(record)
                else:
                    nonmatches.append(record)
            if matches:
                return self.sort_matches(matches, nonmatches)

            matches = []
            nonmatches = []
            for record in self.vault.records:
                if pattern.match('%s%s%s' % (record.group, sep, record.title)):
                    matches.append(record)
                else:
                    nonmatches.append(record)
            if matches:
                return self.sort_matches(matches, nonmatches)

            matches = []
            nonmatches = []
            for record in self.vault.records:
                if pattern.match('%s%s%s' % (record.title, sep, record.user)):
                    matches.append(record)
                else:
                    nonmatches.append(record)
            if matches:
                return self.sort_matches(matches, nonmatches)

        for sep in ".", " ":
            matches = []
            nonmatches = []
            for record in self.vault.records:
                if pattern.match('%s%s%s%s%s' % (record.title, sep, record.group, sep, record.user)):
                    matches.append(record)
                else:
                    nonmatches.append(record)
            if matches:
                return self.sort_matches(matches, nonmatches)

            matches = []
            nonmatches = []
            for record in self.vault.records:
                if pattern.match('%s%s%s' % (record.title, sep, record.group)):
                    matches.append(record)
                else:
                    nonmatches.append(record)
            if matches:
                return self.sort_matches(matches, nonmatches)

        matches = self.find_titles(line)
        nonmatches = list(set(self.vault.records) - set(matches))

        return matches, nonmatches

    def find_titles(self, regexp):
        """Finds titles, username, group, or combination of all 3 matching a
        regular expression. (Case insensitive)"""
        matches = []
        nonmatches = []
        try:
            pat = re.compile(regexp, re.IGNORECASE)
        except:
            print "Invalid regexp: %s" % regexp
            raise
        for record in self.vault.records:
            if pat.match(record.title):
                matches.append(record)
            elif pat.match(record.user):
                matches.append(record)
            elif pat.match(record.group):
                matches.append(record)
            elif pat.match(str(record.uuid)):
                matches.append(record)
            elif pat.match("%s.%s [%s]" % (record.group, record.title, record.user)):
                matches.append(record)
            else:
                nonmatches.append(record)

        matches, _ = self.sort_matches(matches)

        return matches


def main(argv):
    # Options
    usage = "usage: %prog [options] [vault.psafe3]"
    parser = OptionParser(usage=usage)
    parser.add_option("-l", "--ls", dest="do_ls", default=False,
        action="store_true", help="list contents of vault")
    parser.add_option("-s", "--show", dest="do_show", default=None,
        action="store", type="string", help="Show entries matching REGEX",
        metavar="REGEX")
    parser.add_option("-i", "--interactive", dest="interactive", default=False,
        action="store_true", help="Use command line interface")
    parser.add_option("-n", "--new", dest="create_new_vault", default=False,
        action="store_true", help="Create and initialize new vault.")
    parser.add_option("-c", "--console_only", dest="console", default=False,
        action="store_true", help="Disable interaction with clipboard")
    parser.add_option("-p", "--password", dest="passwd", default=False,
        action="store_true", help="Auto adds password to clipboard. (GTK Only)")
    parser.add_option("-e", "--echo", dest="echo", default=False,
        action="store_true", help="Passwords are displayed on the screen")
    parser.add_option("-u", "--uuid", dest="uuid", default=False,
        action="store_true", help="Show uuid while processing passwords")
    parser.add_option("-x", "--export", dest="export", default=False,
        action="store_true", help="Export database to csv")


    (options, args) = parser.parse_args()

    interactiveConsole = InteractiveConsole()

    if (len(args) < 1):
        if (config.recentvaults):
            interactiveConsole.vault_file_name = config.recentvaults[0]
            print "No vault specified, using %s" % interactiveConsole.vault_file_name
        else:
            print "No vault specified, and none found in config."
            sys.exit(2)
    elif (len(args) > 1):
        print "More than one vault specified"
        sys.exit(2)
    else:
        interactiveConsole.vault_file_name = args[0]

    if not os.path.isfile(interactiveConsole.vault_file_name) or options.create_new_vault:
        interactiveConsole.create_vault()
    else:
        while True:
            try:
                interactiveConsole.open_vault()
                config.save()
                break
            except Vault.BadPasswordError:
                pass
            except KeyboardInterrupt:
                print "^C pressed... exiting."
                sys.exit(0)
            except:
                sys.exit(1)
        if options.do_ls:
            interactiveConsole.do_ls("")
            sys.exit(0)
        elif options.do_show:
            interactiveConsole.uuid = options.uuid
            interactiveConsole.echo = options.echo
            interactiveConsole.do_show(options.do_show)
            sys.exit(0)
        elif options.export:
            interactiveConsole.do_export()
            sys.exit(0)

    interactiveConsole.uuid = options.uuid
    interactiveConsole.echo = options.echo
    interactiveConsole.set_prompt()
    try:
        interactiveConsole.cmdloop()
    except KeyboardInterrupt:
        print " ... exiting."

    sys.exit(0)


main(sys.argv[1:])

