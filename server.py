# -*- coding: utf-8 -*-
"""
Created on Wed Nov 25 16:11:11 2020

@author: Guess who
"""
#!/usr/bin/env python

# This is a simple web server for a traffic counting application.
# It's your job to extend it by adding the backend functionality to support
# recording the traffic in a SQL database. You will also need to support
# some predefined users and access/session control. You should only
# need to extend this file. The client side code (html, javascript and css)
# is complete and does not require editing or detailed understanding.

# import the various libraries needed
import http.cookies as Cookie # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer # the heavy lifting of the web server
import urllib # some url parsing support
import base64 # some encoding support
import sqlite3 # used to create database
import hashlib # encrypt password
import numpy as np # import numpy

def access_database(query):
    """
    This module process sql queries without generating output.
    """
    connect = sqlite3.connect('initial_database.db')
    cursor = connect.cursor()
    cursor.execute(query)
    connect.commit()
    connect.close()

def access_database_with_result(query):
    """
    This module process sql queries with output.
    """
    connect = sqlite3.connect('initial_database.db')
    cursor = connect.cursor()
    rows = cursor.execute(query).fetchall()
    connect.commit()
    connect.close()
    return rows

def hash_encode(string):
    """
    This module used to hash input password in
    order to match encoded passwords in the database
    """
    new = hashlib.md5()
    new.update(string.encode('utf-8'))
    password_hash = new.hexdigest()
    return password_hash

# This function builds a refill action that allows part of the
# currently loaded page to be replaced.
def build_response_refill(where, what):
    """
    This function builds a refill action that allows part of the
    currently loaded page to be replaced.
    """
    text = "<action>\n"
    text += "<type>refill</type>\n"
    text += "<where>"+where+"</where>\n"
    medium = base64.b64encode(bytes(what, 'ascii'))
    text += "<what>"+str(medium, 'ascii')+"</what>\n"
    text += "</action>\n"
    return text


# This function builds the page redirection action
# It indicates which page the client should fetch.
# If this action is used, only one instance of it should
# contained in the response and there should be no refill action.
def build_response_redirect(where):
    """
    This function builds the page redirection action
    It indicates which page the client should fetch.
    If this action is used, only one instance of it should
    contained in the response and there should be no refill action.
    """
    text = "<action>\n"
    text += "<type>redirect</type>\n"
    text += "<where>"+where+"</where>\n"
    text += "</action>\n"
    return text

## Decide if the combination of user and magic is valid
def handle_validate(iuser, imagic):
    """
    This function validates if there a session is still in proccess.
    """
    login_session = access_database_with_result("select sessionid from logged_in \
                                                where username='{}'".format(iuser))
    if (len(login_session) != 0) and login_session[0][0] == imagic:
        return True
    return False

## remove the combination of user and magic from the data base, ending the login
def handle_delete_session(iuser, imagic):
    """
    This function helps delete log in record and
    update not-yet-logged-out users to log out.
    """
    del imagic
    access_database("delete from logged_in where username='{}'".format(iuser))
    access_database("update sessions set end_time=datetime('now') \
                    where username='{}' and end_time is null".format(iuser))

## A user has supplied a username (parameters['usernameinput'][0])
## and password (parameters['passwordinput'][0]) check if these are
## valid and if so, create a suitable session record in the database
## with a random magic identifier that is returned.
## Return the username, magic identifier and the response action set.
def handle_login_request(iuser, imagic, parameters):
    """
    Validates log in, then log the user into the
    page, meanwhile updating database to record behaviors.
    """
    iuser = parameters['usernameinput'][0]
    if handle_validate(iuser, imagic) is True:
        text = "<response>\n"
        handle_delete_session(iuser, imagic)

    text = "<response>\n"
    if ('passwordinput' not in parameters.keys()) or ('usernameinput' not in parameters.keys()):
        text += build_response_refill('message', 'Please fill in all sections')
        user = '!'
        magic = ''
    else:
        username, password = parameters['usernameinput'][0], parameters['passwordinput'][0]
        password = hash_encode(password)
        if (username, password) in access_database_with_result('select * from users'):
            duplicates = access_database_with_result("select * from logged_in \
                                                     where username='{}'".format(username))
            if len(duplicates) == 0:
                text += build_response_redirect('/page.html')
                rand_id = str(np.random.randint(0, 9999999999, dtype=np.int64))
                user = username
                if len(rand_id) < 10:
                    zeros = '0'*(10-len(rand_id))
                    magic = zeros + rand_id
                else:
                    magic = rand_id
                access_database("INSERT INTO sessions (sessionid, username, start_time) \
                                VALUES ('{}', '{}', datetime('now'))".format(str(magic), str(user)))
                access_database("INSERT INTO logged_in \
                                VALUES ('{}', '{}')".format(str(magic), str(user)))
            else:
                text += build_response_refill('message', 'User already logged in, try again.')
                handle_delete_session(iuser, imagic)
                user = '!'
                magic = ''
        else: ## The user is not valid
            text += build_response_refill('message', 'Invalid username/password')
            user = '!'
            magic = ''
    text += "</response>\n"
    return [user, magic, text]

## The user has requested a vehicle be added to the count
## parameters['locationinput'][0] the location to be recorded
## parameters['occupancyinput'][0] the occupant count to be recorded
## parameters['typeinput'][0] the type to be recorded
## Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_add_request(iuser, imagic, parameters):
    """
    This function handles all ADD commands. It provides means
    to deal with malformed and malicious inputs. If entries are
    successfully added, update database.
    """
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        #Invalid sessions respond with message
        text += build_response_refill('message', 'Session not valid, please check if logged in.')
    else: ## a valid session so process the addition of the entry.
        location = parameters['locationinput'][0]
        occupancy = parameters['occupancyinput'][0]
        types = parameters['typeinput'][0]
        total_count = access_database_with_result("select count(*) from record where record_id='{}'\
                                                   and flag=0".format(imagic))[0][0]
        occ_pool = ['1', '2', '3', '4']
        type_pool = ['car', 'bus', 'bicycle', 'motorbike', 'van', 'taxi', 'truck', 'other']
        if (occupancy not in occ_pool) or (types not in type_pool):
            text += build_response_refill('message', 'Unknown Entry.')
            text += build_response_refill('total', '{}'.format(total_count))
        else:
            try:
                access_database("INSERT INTO record VALUES \
                                ('{}','{}','{}','{}','{}',datetime('now'),0)\
                                ".format(imagic, iuser, location, types, occupancy))
                total_count = access_database_with_result("select count(*) from record \
                                                          where record_id='{}' and flag=0\
                                                          ".format(imagic))[0][0]
                text += build_response_refill('message', 'Entry added.')
                text += build_response_refill('total', '{}'.format(total_count))
            except:
                text += build_response_refill('message', 'Potential Injection Detected.')
                text += build_response_refill('total', '{}'.format(total_count))
    text += "</response>\n"
    user = iuser
    rand_id = str(np.random.randint(0, 9999999999, dtype=np.int64))
    if len(rand_id) < 10:
        zeros = '0'*(10-len(rand_id))
        magic = zeros + rand_id
    else:
        magic = rand_id
    return [user, magic, text]

## The user has requested a vehicle be removed from the count
## This is intended to allow counters to correct errors.
## parameters['locationinput'][0] the location to be recorded
## parameters['occupancyinput'][0] the occupant count to be recorded
## parameters['typeinput'][0] the type to be recorded
## Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_undo_request(iuser, imagic, parameters):
    """
    This function handles the UNDO command, which eliminates the latest entry with the same
    type. Although instead of remove the record from the database, it flags the record as
    being undone.
    """
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        #Invalid sessions respond with message
        text += build_response_refill('message', 'Session not valid, please check if logged in.')
    else: ## a valid session so process the recording of the entry.
        location = parameters['locationinput'][0]
        occupancy = parameters['occupancyinput'][0]
        types = parameters['typeinput'][0]
        locations = [i[0] for i in access_database_with_result("select location from record")]
        total_count = access_database_with_result("select count(*) from record where \
                                                  record_id='{}' and flag=0".format(imagic))[0][0]
        occ_pool = ['1', '2', '3', '4']
        type_pool = ['car', 'bus', 'bicycle', 'motorbike', 'van', 'taxi', 'truck', 'other']
        if (occupancy not in occ_pool) or (types not in type_pool) or (location not in locations):
            text += build_response_refill('message', 'Unknown Entry.')
            text += build_response_refill('total', '{}'.format(total_count))
        else:
            if total_count != 0:
                access_database("update record set flag=1,time=datetime('now') where rowid=(select rowid from record where type='{}' and record_id='{}' order by time limit 1)".format(types, imagic))
                total_count = access_database_with_result("select count(*) from record where record_id='{}' and flag=0".format(imagic))[0][0]
                text += build_response_refill('message', 'Entry Un-done.')
                text += build_response_refill('total', '{}'.format(total_count))
            else:
                text += build_response_refill('message', 'No Entry to be Un-done.')
                text += build_response_refill('total', '0')
    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]

# This code handles the selection of the back button on the record form (page.html)
# You will only need to modify this code if you make changes elsewhere that break its behaviour
def handle_back_request(iuser, imagic, parameters):
    """
    This code handles the selection of the back button on the record form (page.html)
    You will only need to modify this code if you make changes elsewhere that break its behaviour
    """
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        text += build_response_redirect('/index.html')
    else:
        text += build_response_redirect('/summary.html')
    text += "</response>\n"
    user = ''
    magic = ''
    del parameters
    return [user, magic, text]

## This code handles the selection of the logout button on the summary page (summary.html)
## You will need to ensure the end of the session is recorded in the database
## And that the session magic is revoked.
def handle_logout_request(iuser, imagic, parameters):
    """
    This function handles logout command and alter the database accordingly.
    """
    text = "<response>\n"
    text += build_response_redirect('/index.html')
    handle_delete_session(iuser, imagic)
    user = '!'
    magic = ''
    text += "</response>\n"
    del parameters
    return [user, magic, text]

## This code handles a request for update to the session summary values.
## You will need to extract this information from the database.
def handle_summary_request(iuser, imagic, parameters):
    """
    This code handles a request for update to the session summary values.
    You will need to extract this information from the database.
    """
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        text += build_response_redirect('/index.html')
    else:
        sum_car = access_database_with_result("select count(*) from record where type='car' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_taxi = access_database_with_result("select count(*) from record where type='taxi' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_bus = access_database_with_result("select count(*) from record where type='bus' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_motorbike = access_database_with_result("select count(*) from record where type='motorbike' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_bicycle = access_database_with_result("select count(*) from record where type='bicycle' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_van = access_database_with_result("select count(*) from record where type='van' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_truck = access_database_with_result("select count(*) from record where type='truck' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_other = access_database_with_result("select count(*) from record where type='other' and record_id='{}' and flag=0".format(imagic))[0][0]
        sum_all = access_database_with_result("select count(*) from record where record_id='{}' and flag=0".format(imagic))[0][0]
        text += build_response_refill('sum_car', '{}'.format(sum_car))
        text += build_response_refill('sum_taxi', '{}'.format(sum_taxi))
        text += build_response_refill('sum_bus', '{}'.format(sum_bus))
        text += build_response_refill('sum_motorbike', '{}'.format(sum_motorbike))
        text += build_response_refill('sum_bicycle', '{}'.format(sum_bicycle))
        text += build_response_refill('sum_van', '{}'.format(sum_van))
        text += build_response_refill('sum_truck', '{}'.format(sum_truck))
        text += build_response_refill('sum_other', '{}'.format(sum_other))
        text += build_response_refill('total', '{}'.format(sum_all))
        text += "</response>\n"
        user = ''
        magic = ''
        del parameters
    return [user, magic, text]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    """ Connecting to the front end. """
    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the GET parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        if self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200) #respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)
            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    [user, magic, text] = handle_login_request(user_magic[0], user_magic[1], parameters)
                    #The result to a login attempt will be to set
                    #the cookies to identify the session.
                    set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, text] = handle_add_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, text] = handle_undo_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, text] = handle_back_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, text] = handle_summary_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, text] = handle_logout_request(user_magic[0], user_magic[1], parameters)
                    if user == '!': # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    text = "<response>\n"
                    text += build_response_refill('message', 'Internal Error: Command not recognised.')
                    text += "</response>\n"

            else:
                # There was no command present, report that to the user.
                text = "<response>\n"
                text += build_response_refill('message', 'Internal Error: Command not found.')
                text += "</response>\n"
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))
        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return

# This is the entry point function to this code.
def run():
    """ Running backend program """
    print('starting server...')
    ## You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server...')
    httpd.serve_forever() # This function will not return till the server is aborted.

run()
