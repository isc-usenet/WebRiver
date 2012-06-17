#!/usr/bin/env python2.7
# -*- coding: utf8 -*-

# COPYDOWN (C) You
# All code related to WebRiver and code contained in this file
# is released fully into the public domain

from gevent import monkey
monkey.patch_all()
import gevent
from gevent import queue, pool
from gevent.event import Event
from gevent.coros import RLock
from gevent.pywsgi import WSGIServer, WSGIHandler
from gevent import socket as gsocket
from jinja2 import FileSystemLoader
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, Response, abort
from ConfigParser import SafeConfigParser
from random import randint
import os
import sys
import ssl
import time
import socket
import logging
import gzip
import bz2
import zipfile
import binascii
import subprocess
import shutil
import fcntl
import urllib2
import codecs
import itertools
import _yenc
from cStringIO import StringIO
from xml.dom.minidom import getDOMImplementation, parseString

try:
    import simplejson as json
except ImportError:
    import json

logging.basicConfig(level=logging.INFO)
config = SafeConfigParser()
app = Flask('__main__')
app.debug = True
app.jinja_loader = FileSystemLoader(os.path.realpath(os.path.join(
                                os.path.dirname(__file__), 'templates')))

# Global Variables
logs_count = 1
logs = {
    0: {'type': 'Info', 'message': 'WebRiver started'},
}
riverfiles_count = 0
riverfiles = {}
rivermetas_count = 0
rivermetas = {}
rivers_count = 0
rivers = {}
sessions_count = 0
sessions = {}
streams = {}
streamsbw = {}

def load_config():
    if os.path.exists(os.path.expanduser('~/.webriver/')) and \
       not os.path.isdir(os.path.expanduser('~/.webriver')):
        shutil.rmtree(os.path.expanduser('~/.webriver/'))
    if not os.path.exists(os.path.expanduser('~/.webriver')):
           os.mkdir(os.path.expanduser('~/.webriver'))
           os.mkdir(os.path.expanduser('~/.webriver/subscriptions'))
           os.mkdir(os.path.expanduser('~/.webriver/downloaded'))
           os.mkdir(os.path.expanduser('~/.webriver/metadata'))
           os.mkdir(os.path.expanduser('~/.webriver/rivers'))
    config.read(['local.cfg', os.path.expanduser('~/.webriver/webriver.cfg')])

c = config.get
ci = config.getint
cb = config.getboolean

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == c('webriver','username') and password == c('webriver','password')

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if is_configured() and cb('webriver','auth'):
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
        return f(*args, **kwargs)
    return decorated

def is_configured():
    return config.has_section('usenet')

def session_river(session):
    global sessions, rivers
    out = {}
    if not session in sessions:
        # New session, add everything
        for i in rivers:
            out[i] = rivers[i]['update']
        return out
    else:
        sess = sessions[session]['rivers']
        # Check for updated rivers
        out['update'] = {}
        for i in set(rivers.keys()).intersection(set(sess.keys())):
            if rivers[i]['update'] != sess[i]:
                out['update'][str(i)] = rivers[i].copy()
                del out['update'][str(i)]['update']
                del out['update'][str(i)]['name']
                del out['update'][str(i)]['filename']
                del out['update'][str(i)]['description']
                del out['update'][str(i)]['nfo']
                del out['update'][str(i)]['active']
                sess[i] = rivers[i]['update']
        if not len(out['update']):
            del out['update']
        
        # Check for new rivers
        out['new'] = {}
        for i in set(rivers.keys()).difference(set(sess.keys())):
            out['new'][str(i)] = rivers[i]
            sess[i] = rivers[i]['update']
        if not len(out['new']):
            del out['new']
        
        # Check for deleted rivers
        out['delete'] = []
        for i in set(sess.keys()).difference(set(rivers.keys())):
            out['delete'].append(i)
            del sess[i]
        if not len(out['delete']):
            del out['delete']
        return out
        
def session_logs(session):
    global sessions, logs
    out = {}
    if not session in sessions:
        return set(logs.keys())
    else:
        sess = sessions[session]['logs']
        out['new'] = {}
        for i in set(logs.keys()).difference(sess):
            out['new'][str(i)] = logs[i]
            sess.add(i)
        if not len(out['new']):
            del out['new']
        
        out['delete'] = []
        for i in sess.difference(set(logs.keys())):
            out['delete'].append(i)
            sess.remove(i)
        if not len(out['delete']):
            del out['delete']
        
        return out

def add_log(ltype, lmessage, sid):
    global logs, logs_count
    lid = logs_count
    logs_count += 1
    logs[lid] = {'type': ltype, 'message': lmessage}
    sessions[sid]['logs'].add(lid)
    return lid

def delete_log(lid, sid):
    global logs
    if lid in logs:
        del logs[lid]
    sessions[sid]['logs'].remove(lid)
    
def add_river(rid, sid):
    global rivers_count, rivers, sessions
    src = riverfiles[rid]

    name = src['name']
    desc = name
    nfo = src['nfo']
    
    if 'filemeta' in src:
        if 'name' in src['filemeta']:
            name = src['filemeta']['name']
        if 'description' in src['filemeta']:
            desc = src['filemeta']['description']
    
    rivers[rid] = {'name': name, 'description': desc, 'bytes': int(src['bytes']), 'filename': src['name'], 'active': {}, 'isDownloading': False, 'nfo': nfo}
    if cb('webriver', 'pre') or cb('webriver','auto'):
        rivers[rid]['isRecording'] = True
    else:
        rivers[rid]['isRecording'] = False
    rivers[rid]['progress'] = 0
    rivers[rid]['update'] = 0
    rivers[rid]['recorded'] = 0
    rivers[rid]['total'] = total_articles(src['segments'])
    sessions[sid]['rivers'][rid] = 0
    if c('webriver', 'auto') == 'on':
        river_load(rid, -1)
    elif c('webriver', 'pre') == 'on':
            river_load(rid, 10)
    save_metadata()

def delete_river(rid, sid):
    global rivers, sessions
    del rivers[rid]
    del sessions[sid]['rivers'][rid]
    save_metadata()

def clear_rivers(sid):
    global rivers, sessions
    rivers = {}
    rivers_count = 0
    sessions[sid]['rivers'] = {}
    location = os.path.expanduser('~/.webriver/downloaded/')
    shutil.rmtree(location)
    os.mkdir(location)
    save_metadata()

def get_configuration():
    global config
    out = {'u': {}, 'wr': {}}
    if config.has_section('usenet-backup'):
        out['ub'] = {}
        out['ub']['server'] = config.get('usenet-backup', 'server')
        out['ub']['port'] = config.get('usenet-backup', 'port')
        out['ub']['connect'] = config.get('usenet-backup', 'connections')
        out['ub']['ssl'] = config.get('usenet-backup', 'ssl')
        if config.has_option('usenet-backup','username'):
            out['ub']['username'] = config.get('usenet-backup','username')
        if config.has_option('usenet-backup','password'):
            out['ub']['password'] = True
    out['u']['server'] = config.get('usenet', 'server')
    out['u']['port'] = config.get('usenet', 'port')
    out['u']['connect'] = config.get('usenet', 'connections')
    out['u']['ssl'] = config.get('usenet', 'ssl')
    if config.has_option('usenet','username'):
        out['u']['username'] = config.get('usenet','username')
    if config.has_option('usenet','password'):
        out['u']['password'] = True
    
    if config.has_option('webriver','auth'):
        out['wr']['username'] = config.get('webriver','username')
    out['wr']['pvr'] = config.get('webriver','pvr')
    out['wr']['auto'] = config.get('webriver','auto')
    out['wr']['pre'] = config.get('webriver','pre')
    return out

def grab_rlink(link):
    global river_queue
    if not link.startswith("river:"):
        raise Exception, "Not a river link"
    result = gevent.event.AsyncResult()
    art = link[6:]
    rdata = ''
    while True:
        river_queue.put((art, result))
        result, (headers, data) = result.get()
        if data[:7] == '=ybegin':
            data = data[data.find('\r\n')+2:]
        if data[:6] == '=ypart':
            data = data[data.find('\r\n')+2:]
        if data.rfind('=yend') != -1:
            data = data[:data.rfind('\r\n')]
        data = data.replace('\r\n..','\r\n.')
        data, crc, _ = _yenc.decode_string(data)
        rdata += data
        if headers['X-RLink-Next'] == 'END':
            break
        else:
            art = headers['X-RLink-Next']
    crc = "%08x" % (binascii.crc32(rdata) & 0xffffffff)
    hcrc = headers['X-RLink-Crc'].lower()
    if not crc == hcrc:
        print "INVALID RLINK CRC %s HCRC %s" % (crc, hcrc)
        print "Ignoring until release 2"
    return bz2.decompress(data)
    
def grab_river(river):
    global river_queue
    data = urllib2.urlopen(river).read()
    return data

def xml2document(data):
    "Converts river xml into a workable document (which can also be JSONified)"
    riverfile = parseString(data)
    rdoc = riverfile.documentElement
    if rdoc.tagName != 'river':
        return {'error': 'Not a valid river file'}
    rfiles = rdoc.getElementsByTagName('file')
    if len(rfiles) == 0:
        return {'error': 'No files in this river file'}
    river = {'rivermeta': {}, 'files': []}
    rmeta = rdoc.getElementsByTagName('rivermeta')
    if len(rmeta) > 0:
        for i in rmeta[0].childNodes:
            if i.nodeType != i.ELEMENT_NODE:
                continue
            river['rivermeta'][i.nodeName] = i.firstChild.nodeValue.strip()
    for i in rfiles:
        rfile = {'name': i.getAttribute('name'), 'bytes': int(i.getAttribute('bytes')), 'segments': [], 'filemeta': {}}
        rfmeta = i.getElementsByTagName('filemeta')
        if len(rfmeta) > 0:
            for j in rfmeta[0].childNodes:
                if j.nodeType != j.ELEMENT_NODE:
                    continue
                rfile['filemeta'][j.nodeName] = j.firstChild.nodeValue.strip()
        rsegments = i.getElementsByTagName('segment')
        for j in rsegments:
            rsegment = {'name': j.getAttribute('name'), 'bytes': int(j.getAttribute('bytes')), 'articles': [], 'pars': []}
            for k in j.getElementsByTagName('article'):
                rarticle = k.firstChild.nodeValue.strip()
                rsegment['articles'].append({'bytes': int(k.getAttribute('bytes')), 'crc': k.getAttribute('crc'), 'article': rarticle})
            for k in j.getElementsByTagName('par'):
                rarticle = k.firstChild.nodeValue.strip()
                rsegment['pars'].append({'bytes': int(k.getAttribute('bytes')), 'name': k.getAttribute('name'), 'article': rarticle})
            rfile['segments'].append(rsegment)
        river['files'].append(rfile)
    return river

def save_metadata():
    global riverfiles_count, riverfiles, rivers_count, rivers
    open(os.path.expanduser('~/.webriver/metadata/rivers.json'),'w').write(json.dumps([riverfiles_count, riverfiles, rivers_count, rivers]))

def load_metadata():
    global riverfiles_count, riverfiles, rivers_count, rivers
    if not os.path.exists(os.path.expanduser('~/.webriver/metadata/rivers.json')):
        return
    riverfiles_count, riverfiles, rivers_count, rivers = json.loads(open(os.path.expanduser('~/.webriver/metadata/rivers.json')).read())
    for i in rivers:
        rivers[i]['update'] = 0
        rivers[i]['isDownloading'] = False
        rivers[i]['isRecording'] = False
        rivers[i]['progress'] = 0
        rivers[i]['active'] = {}

def process_river(filename, data):
    global riverfiles_count, riverfiles
    if data[:3] == 'BZh': # .river.bz2
        data = bz2.decompress(data)
    elif data[:3] == '\x1f\x8b\x08': # .river.gz
        gfile = gzip.GzipFile(fileobj=StringIO(data))
        data = gfile.read()
        del gfile
    elif data[:4] == 'PK\x03\x04': # .river.zip
        zfile = zipfile.PyZipFile(StringIO(data))
        if len(zfile.filelist) != 1:
            return {'error': 'Zip file does not contain only one file'}
        data = zfile.read(zfile.filelist[0].filename)
        del zfile
    data = xml2document(data)
    out = {'files': []}
    if 'rivermeta' in data and 'name' in data['rivermeta']:
        out['name'] = data['rivermeta']['name']
    else:
        out['name'] = filename
    if 'rivermeta' in data and 'nfo' in data['rivermeta']:
        rivernfo = data['rivermeta']['nfo']
    else:
        rivernfo = None
    for i in data['files']:
        rfid = str(riverfiles_count)
        riverfiles_count += 1
        riverfiles[rfid] = i
        if 'filemeta' in i:
            if 'name' in i['filemeta']:
                fname = i['filemeta']['name']
            else:
                fname = i['name']
                
            if 'description' in i['filemeta']:
                desc = i['filemeta']['description']
            else:
                desc = fname
                
            if 'nfo' in i['filemeta']:
                filenfo = i['filemeta']['nfo']
            else:
                filenfo = rivernfo
            riverfiles[rfid]['nfo'] = filenfo
        out['files'].append({'id': rfid, 'name': fname, 'filename': i['name'], 'description': desc, 'nfo': filenfo, 'bytes': int(i['bytes'])})
    return out

@app.route('/')
def main():
    if not is_configured():
        return redirect(url_for('cfg'))
    else:
        return redirect(url_for('webriver'))

@app.route('/cfg')
def cfg():
    return render_template('configure.html')
        
@app.route('/wr')
@requires_auth
def webriver():
    if not is_configured():
        return redirect(url_for('cfg'))
    else:
        return render_template('main.html')
    
@app.route('/init_state')
@requires_auth
def init_state():
    global sessions, log, bandwidth_down, bandwidth_up, streams, sessions_lock, sessions_count
    if not is_configured():
        return '{\"not_configured\": true}'
    download = {
        'downlink': bandwidth_down,
        'uplink': bandwidth_up,
        'ips': streams
    }
    session = sessions_count
    sessions_count += 1
    sessions[session] = {'logs': session_logs(session), 'rivers': session_river(session)}
    out = {'session': session, 'download': download, 'rivers': rivers, 'logs': logs}
    if c('webriver','pvr') == 'on':
        out['pvr'] = True
    return json.dumps(out)
    
@app.route('/get_config')
@requires_auth
def get_config():
    return json.dumps(get_configuration())
    
@app.route('/update_state')
@requires_auth
def update_state():
    global sessions, bandwidth_down, bandwidth_up, rivers
    if not is_configured():
        return '{\"not_configured\": true}'
    if not 'session' in request.args:
        return '{}'
    session = int(request.args['session'])
    if not session in sessions.keys():
        return Response(response=init_state(), content_type='application/json')
    download = {
        'downlink': bandwidth_down,
        'uplink': bandwidth_up,
        'ips': streams
    }
    rivs = session_river(session)
    logs = session_logs(session)
    out = {'download': download}
    if len(logs):
        out['logs'] = logs
    if len(rivers):
        out['rivers'] = rivs
    return json.dumps(out)

@app.route('/delete_log_row')
@requires_auth
def delete_log_row():
    global sessions, logs
    if not 'session' in request.args or not 'row' in request.args:
        return '{}'
    session = int(request.args['session'])
    lid = int(request.args['row'])
    if not session in sessions.keys():
        return 'false'
    delete_log(lid, session)
    return 'true'

@app.route('/clear_logs')
@requires_auth
def clear_logs():
    global sessions, logs
    if not 'session' in request.args:
        return '{}'
    session = int(request.args['session'])
    if not session in sessions.keys():
        return 'false'
    logs = {}
    return 'true'

@app.route('/add_rivers', methods=['POST'])
@requires_auth
def add_rivers():
    if not 'session' in request.args:
        return 'false'
    if not 'add' in request.form:
        return 'false'
    session = int(request.args['session'])
    add = json.loads(request.form['add'])
    out = {}
    for i in add:
        add_river(str(i), session)
        out[str(i)] = {'progress': 0, 'isDownloading': rivers[str(i)]['isDownloading'], 'isRecording': rivers[str(i)]['isRecording']}
    return json.dumps(out)

@app.route('/delete_river')
@requires_auth
def do_delete_river():
    if not 'session' in request.args:
        return 'false'
    if not 'row' in request.args:
        return 'false'
    session = int(request.args['session'])
    rid = request.args['row']
    delete_river(rid, session)
    return 'true'

@app.route('/record_river')
@requires_auth
def record_river():
    if not 'row' in request.args:
        return 'false'
    rid = request.args['row']
    river_load(rid, -1)
    progress = int(float(rivers[rid]['recorded'])/float(rivers[rid]['total'])*100.0)
    return json.dumps({'id': rid, 'progress': progress, 'isDownloading': rivers[rid]['isDownloading'], 'isRecording': rivers[rid]['isRecording']})
    
@app.route('/record_river_stop')
@requires_auth
def record_river_stop():
    if not 'row' in request.args:
        return 'false'
    rid = request.args['row']
    rivers[rid]['isRecording'] = False
    rivers[rid]['update'] += 1
    if not rivers[rid]['isDownloading']:
        rivers[rid]['progress'] = 0
    return json.dumps({'id': rid, 'progress': rivers[rid]['progress'], 'isDownloading': rivers[rid]['isDownloading'], 'isRecording': rivers[rid]['isRecording']})

@app.route('/clear_rivers')
@requires_auth
def do_clear_rivers():
    if not 'session' in request.args:
        return 'false'
    session = int(request.args['session'])
    clear_rivers(session)
    return 'true'

'''@app.route('/sub_complete')
@requires_auth
def sub_complete():
    string = request.args['s']
    if string == '':
        return json.dumps(['tv.','movies.'])
    if string == 'tv.':
        return json.dumps(['tv.comedy.', 'tv.nothing'])
    if string == 'tv.comedy.':
        return json.dumps(['tv.comedy.catshow', 'tv.comedy.dogshow'])
    if string == 'movies.':
        return json.dumps(['movies.nothing'])
    return json.dumps([])'''
    
@app.route('/test_connection')
def test_connection():
    server = request.args['server']
    port = int(request.args['port'])
    ssl = request.args['ssl'] == 'true'
    username = request.args['username']
    password = request.args['password']
    if is_configured():
        if password == 'WR_DO_NOT_CHANGE_THIS_PASSWORD_U':
            password = config.get('usenet','password')
        elif password == 'WR_DO_NOT_CHANGE_THIS_PASSWORD_UB':
            password = config.get('usenet-backup','password')
    return json.dumps(nntp_test(server, port, ssl, username, password))
        
@app.route('/configure', methods=['POST'])
def configure():
    logging.info('Validating Configuration')
    no_redirect = False
    if is_configured():
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return "Already configured."
        no_redirect = True
    if request.form['un-server'] == "":
        return "Server validation failed"
    if request.form['un-port'] == "":
        return "Server validation failed"
    if request.form['un-connect'] == "":
        return "Server validation failed"
    if 'unb-enabled' in request.form:
        if request.form['unb-server'] == "":
            return "Server validation failed"
        if request.form['unb-port'] == "":
            return "Server validation failed"
        if request.form['unb-connect'] == "":
            return "Server validation failed"
    logging.info('Starting Configuration')
    if not config.has_section('usenet'):
        config.add_section('usenet')
    config.set('usenet', 'server', request.form['un-server'])
    config.set('usenet', 'username', request.form['un-username'])
    if not no_redirect and request.form['un-password'] == 'WR_DO_NOT_CHANGE_THIS_PASSWORD_U':
        config.set('usenet', 'password', request.form['un-password'])
    config.set('usenet', 'port', request.form['un-port'])
    config.set('usenet', 'connections', request.form['un-connect'])
    config.set('usenet', 'ssl','on' if ('un-ssl' in request.form and request.form['un-ssl'] == 'on') else 'off')
    if 'unb-enabled' in request.form:
        if not config.has_section('usenet-backup'):
            config.add_section('usenet-backup')
        config.set('usenet-backup', 'server', request.form['unb-server'])
        config.set('usenet-backup', 'username', request.form['unb-username'])
        if not no_redirect and request.form['unb-password'] == 'WR_DO_NOT_CHANGE_THIS_PASSWORD_UB':
            config.set('usenet-backup', 'password', request.form['unb-password'])
        config.set('usenet-backup', 'port', request.form['unb-port'])
        config.set('usenet-backup', 'connections', request.form['unb-connect'])
        config.set('usenet-backup', 'ssl','on' if ('un-ssl' in request.form and request.form['un-ssl'] == 'on') else 'off')
    else:
        if config.has_section('usenet-backup'):
            config.remove_section('usenet-backup')
    if not config.has_section('webriver'):
        config.add_section('webriver')
    if 'wr-auth' in request.form:
        config.set('webriver', 'auth', 'on')
        config.set('webriver', 'username', request.form['wr-username'])
        if not no_redirect and request.form['wr-password'] == 'WR_DO_NOT_CHANGE_THIS_PASSWORD_WR':
            config.set('webriver', 'password', request.form['wr-password'])
    else:
        config.set('webriver', 'auth', 'off')
    if 'wr-pvr' in request.form:
        config.set('webriver', 'pvr', 'on')
    else:
        config.set('webriver', 'pvr', 'off')
    if 'wr-auto' in request.form:
        config.set('webriver', 'auto', 'on')
    else:
        config.set('webriver', 'auto', 'off')
    if 'wr-pre' in request.form:
        config.set('webriver', 'pre', 'on')
    else:
        config.set('webriver', 'pre', 'off')
    config.write(open(os.path.expanduser('~/.webriver/webriver.cfg'),'w'))
    logging.info('Configuration saved')
    if no_redirect:
        return "configured"
    else:
        return redirect(url_for('main'))

@app.route('/add_upload', methods=['POST'])
@requires_auth
def upload():
    data = request.files['river'].stream.read()
    files = process_river(request.files['river'].filename, data)
    return json.dumps(files)
    
@app.route('/add_url', methods=['POST'])
@requires_auth
def url():
    print repr(request.form)
    if request.form['river'].startswith('river:'):
        data = grab_rlink(request.form['river'])
    else:
        data = grab_river(request.form['river'])
    files = process_river("River Link", data)
    return json.dumps(files)

@app.route('/nfo/<rid>')
def nfo(rid):
    print rivers[rid]
    if not 'nfo' in rivers[rid]:
        return abort(404)
    if rivers[rid]['nfo'] == None:
        return abort(404)
    print rivers[rid]['nfo']
    article = dlayer.get_article(rivers[rid]['nfo'])[0].decode('cp437').encode('utf-8')
    out = '<!DOCTYPE html>\n<html>\n<head></head><body style=\"background-color:#000;color:#fff\"><pre>'
    try:
        out += article.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    except:
        return "Error retrieving NFO file."
    out += '</pre></body></html>'
    return Response(out, headers={'Content-Type': 'text/html; charset=UTF-8'})

@app.route('/play/<rid>/<filename>')
def play(rid, filename):
    global streams, streamsbw, bytes_up
    start = 0
    end = None
    rangehead = False
    status = '200 OK'
    if 'Range' in request.headers:
        start, end = parse_range(request.headers['Range'])
        rangehead = True
        status = '206 Partial Content'
    addr = request.remote_addr
    port = request.environ['webriver.remote_port']
    if not rid in rivers or rivers[rid]['filename'] != filename:
        if str(port) in rivers[rid]['active']:
            del rivers[rid]['active'][str(port)]
        if len(rivers[rid]['active']) == 0:
            rivers[rid]['isDownloading'] = False
            rivers[rid]['update'] += 1
        if addr in streams:
            if port in streams[addr]:
                del streams[addr][port]
            if len(streams[addr]) == 0:
                del streams[addr]
        return abort(404)
    playfile = flayer.open(rid)
    def play_iter(playfile):
        global bytes_up, flayer
        while True:
            chunk = playfile.read(min(16384, end+1-playfile.pos))
            if len(chunk) == 0:
                del rivers[rid]['active'][str(port)]
                if len(rivers[rid]['active']) == 0:
                    rivers[rid]['isDownloading'] = False
                    rivers[rid]['update'] += 1
                if addr in streams:
                    if port in streams[addr]:
                        del streams[addr][port]
                    if len(streams[addr]) == 0:
                        del streams[addr]
                return
            yield chunk
            streamsbw[addr][port]['bytes'] += len(chunk)
            bytes_up += len(chunk)
            if len(rivers[rid]['active']) == 1:
                rivers[rid]['progress'] = int(float(playfile.pos) / float(playfile.fsize) * 100.0)
                rivers[rid]['update'] += 1
                
    headers = {'Content-Length': playfile.fsize}
    if end == None:
        end = playfile.fsize-1
    if start > playfile.fsize:
        if str(port) in rivers[rid]['active']:
            del rivers[rid]['active'][str(port)]
        if len(rivers[rid]['active']) == 0:
            rivers[rid]['isDownloading'] = False
            rivers[rid]['update'] += 1
        if addr in streams:
            if port in streams[addr]:
                del streams[addr][port]
            if len(streams[addr]) == 0:
                del streams[addr]
        if end == None: end = playfile.fsize
        return Response("Out of range", status="416 Requested Range Not Satisfiable")
    if start == playfile.fsize:
        headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, playfile.fsize)
        headers['Content-Length'] = str(end-start)
        return Response("", status="206 Partial Content", headers=headers, mimetype='application/octet-stream')
    if rangehead:
        playfile.seek(start)
        headers['Content-Range'] = 'bytes %d-%d/%d' % (start, end, playfile.fsize)
        headers['Content-Length'] = str(end-start)
    return Response(play_iter(playfile), status=status, headers=headers, mimetype='application/octet-stream')
    
def parse_range(rangehead):
    start, end = rangehead[6:].split('-', 1)
    if end == '':
        return int(start), None
    return int(start), int(end)

def total_articles(segments):
    total = 0
    for i in segments:
        total += len(i['articles'])
    return total

''' --- Background functions --- '''

def river_load(rid, num):
    global rivers
    rivers[rid]['isRecording'] = True
    rivers[rid]['update'] += 1
    if not rivers[rid]['isDownloading']:
        rivers[rid]['progress'] = int(float(rivers[rid]['recorded'])/float(rivers[rid]['total'])*100.0)
    gevent.spawn(clayer.record_articles, rid, num)

def timer_calculate_bandwidth():
    while True:
        gevent.sleep(1)
        try:
            calculate_bandwidth()
        except:
            continue

last_bytes_check = time.time()
bytes_down = 0
bytes_up = 0
bandwidth_down = 0
bandwidth_up = 0
def calculate_bandwidth():
    global bytes_down, bytes_up, bandwidth_down, bandwidth_up, last_bytes_check, streamsbw
    last = last_bytes_check
    now = time.time()
    bandwidth_down = int(bytes_down / (now-last))
    bandwidth_up = int(bytes_up / (now-last))
    last_bytes_check = now
    bytes_down = 0
    bytes_up = 0
    for i in streamsbw:
        for j in streamsbw[i]:
            try:
                streams[i][j]['link'] = int(streamsbw[i][j]['bytes'] / (now-last))
                streamsbw[i][j]['bytes'] = 0
            except:
                continue

class FileObject:
    def __init__(self, clayer, rfid):
        global riverfiles
        self.clayer = clayer
        #self.fid = fid
        self.pos = 0
        self.bytes = bytes
        self.fsize = riverfiles[rfid]['bytes']
        self.segments = riverfiles[rfid]['segments']
        self.rid = rfid
        self.current_path = None
        self.current_buffer = ''
    
    def read(self, amount):
        if self.current_buffer == '':
            self.current_path, offset = self.get_article_path(self.pos)
            if (self.current_path[0] == -1):
                return ''
            finished, f = self.clayer.get_article(self.rid, self.segments, self.current_path)
            self.read_ahead(5)
            if not finished:
                result, data = f.get()
                if not result:
                    raise Exception, data
            else:
                data = f
            self.current_buffer = data[offset:]
        while True:
            if len(self.current_buffer) < amount:
                self.current_path, offset = self.get_next_article_path(self.current_path)
                if (self.current_path[0] == -1):
                    self.pos += len(self.current_buffer)
                    out = self.current_buffer
                    self.current_buffer = ''
                    return out
                result, f = self.clayer.get_article(self.rid, self.segments, self.current_path)
                self.read_ahead(5)
                if result:
                    data = f
                if not result:
                    result, data = f.get()
                if not result:
                    raise Exception, data
                self.current_buffer += data
            else:
                out = self.current_buffer[:amount]
                self.current_buffer = self.current_buffer[amount:]
                self.pos += amount
                return out
    
    def seek(self, byte):
        if (byte <= self.fsize):
            self.pos = byte
        self.current_path = self.get_article_path(byte)
        self.current_buffer = ''

    def read_ahead(self, articles):
        if 'recover' in self.clayer.jobs:
            print "Not reading ahead due to recovery in progress"
            return
        path, _ = self.get_next_article_path(self.current_path)
        if path[0] == -1:
            return
        for _ in xrange(articles):
            res, f = self.clayer.get_article(self.rid, self.segments, path)
            path, _ = self.get_next_article_path(path)
            if path[0] == -1:
                return

    def get_article_path(self, byte):
        segnum = -1
        artnum = -1
        sumbyte = 0
        offset = 0
        for i in range(len(self.segments)):
            if byte < sumbyte + self.segments[i]['bytes']:
                segnum = i
                for j in range(len(self.segments[i]['articles'])):
                    if byte < sumbyte + self.segments[i]['articles'][j]['bytes']:
                        artnum = j
                        offset = byte - sumbyte
                        return (segnum, artnum), offset
                    else:
                        sumbyte += self.segments[i]['articles'][j]['bytes']
            else:
                sumbyte += self.segments[i]['bytes']
        offset = byte - sumbyte
        return (segnum, artnum), offset
        
    def get_next_article_path(self, current_path):
        s, a = current_path
        if a+1 >= len(self.segments[s]['articles']):
            if s+1 >= len(self.segments):
                return (-1, -1), 0
            return (s+1, 0), 0
        return (s, a+1), 0

class FileLayer:
    def __init__(self, clayer):
        self.clayer = clayer
        
    def open(self, rfid):
        return FileObject(self.clayer, rfid)
        
debug_recover = None
class CacheLayer:
    def __init__(self, dlayer, location=None):
        self.dlayer = dlayer
        self.hashcache = {}
        self.rollcache = []
        self.jobs = {}
        if not is_configured():
            raise Exception, "WebRiver must be configured before cache starts"
        if cb('webriver', 'pvr'):
            self.store = self.hddstore
            self.grab = self.hddgrab
            if not location:
                location = os.path.expanduser('~/.webriver/downloaded/')
            self.location = location
        else:
            self.store = self.memstore
            self.grab = self.memgrab

    def get_article(self, rid, segments, path):
        data = self.grab(rid, segments, path)
        if data:
            return (True, data)
        messageid = segments[path[0]]['articles'][path[1]]['article']
        if messageid in self.jobs:
            return (False, self.jobs[messageid])
        f = gevent.event.AsyncResult()
        gevent.spawn(self.do_get_article, f, rid, segments, path)
        self.jobs[messageid] = f
        return (False, f)

    def do_get_article(self, finish, rid, segments, path):
        article = segments[path[0]]['articles'][path[1]]
        messageid = segments[path[0]]['articles'][path[1]]['article']
        data, crc = self.dlayer.get_article(article['article'])
        crc = '%08x' % ((crc^-1) & 0xffffffff)
        rcrc = article['crc'].lower()
        if crc != rcrc:
            print "CAUGHT INVALID CRC32"
            print "article", crc, "river", rcrc
            if 'recover:'+str(path[0]) in self.jobs:
                print "waiting for recovery"
                data = self.jobs['recover:'+str(path[0])].get()
                print "done waiting for recovery"
            else:
                self.jobs['recover:'+str(path[0])] = gevent.event.AsyncResult()
                print "recovering"
                data = self.recover(rid, segments, path)
                print "done recovering"
                self.jobs['recover:'+str(path[0])].set(data)
        self.store(rid, segments, path, data)
        if messageid in self.jobs:
            del self.jobs[messageid]
        finish.set((True, data))
        
    def record_articles(self, rid, num):
        if not rivers[rid]['isRecording']:
            print "River not recording"
            return
        if num == -1:
            print "Recording everything"
        else:
            print "Preloading %d articles" % num
        segments = riverfiles[rid]['segments']
        if num != -1 and num <= rivers[rid]['recorded']:
            print "Already recorded up to this point"
            return
        workers = 5
        loadqueue = gevent.queue.Queue(workers)
        jobs = []
        for i in xrange(workers):
            jobs.append(gevent.spawn(self.do_record_article_thread, rid, loadqueue))
        current = 0
        if num == -1:
            num = rivers[rid]['total']
        for i in xrange(len(segments)):
            for j in xrange(len(segments[i]['articles'])):
                if current < rivers[rid]['recorded']:
                    current += 1
                    continue
                if not rivers[rid]['isRecording']:
                    for i in xrange(workers):
                        loadqueue.put(0)
                    gevent.joinall(jobs)
                    return
                if current >= num:
                    print "Completed"
                    for i in xrange(workers):
                        loadqueue.put(0)
                    gevent.joinall(jobs)
                    print "Fully Completed"
                    if not rivers[rid]['isDownloading']:
                        rivers[rid]['progress'] = 0
                    rivers[rid]['isRecording'] = False
                    rivers[rid]['update'] += 1
                    return
                loadqueue.put([i,j])
                current += 1
        print "End Completed"
        for i in xrange(workers):
            loadqueue.put(0)
        gevent.joinall(jobs)
        print "End Fully Completed"
        rivers[rid]['isRecording'] = False
        rivers[rid]['update'] += 1
    
    def do_record_article_thread(self, rid, queue):
        segments = riverfiles[rid]['segments']
        while True:
            try:
                path = queue.get(timeout=10)
                if path == 0:
                    return
                res, f = self.get_article(rid, segments, path)
                if not res:
                    f.get()
                rivers[rid]['recorded'] += 1
                if not rivers[rid]['isDownloading'] and rivers[rid]['isRecording']:
                    rivers[rid]['update'] += 1
                    rivers[rid]['progress'] = int(float(rivers[rid]['recorded'])/float(rivers[rid]['total'])*100.0)
            except gevent.queue.Empty:
                if not rivers[rid]['isRecording']:
                    return
    
    def recover(self, rid, segments, path):
        global debug_recover
        self.jobs['recover'] = True
        if not os.path.exists(self.location+rid+'/'):
            os.mkdir(self.location+rid+'/')
        if not os.path.exists(self.location+rid+'/recover'):
            os.mkdir(self.location+rid+'/recover')
        seg = path[0]
        s = segments[seg]
        print repr(s)
        outfile = open(self.location+rid+'/recover/'+s['name'], 'w')
        arts_in = {}
        pars_in = {}
        arts_out = {}
        pars_out = {}
        for i in range(len(s['articles'])):
            data = self.grab(rid, segments, [path[0], i])
            mid = s['articles'][i]['article']
            if data == None:
                arts_in[i] = gevent.spawn(self.dlayer.get_article, mid)
            else:
                arts_out[i] = data
        for i in range(len(s['pars'])):
            mid = s['pars'][i]['article']
            name = s['pars'][i]['name']
            pars_in[name] = gevent.spawn(self.dlayer.get_article, mid)
        for i in arts_in:
            data, crc = arts_in[i].get()
            arts_out[i] = data
        for i in pars_in:
            data, crc = pars_in[i].get()
            pars_out[i] = data
        for i in arts_out:
            outfile.write(arts_out[i])
        outfile.close()
        for i in pars_out:
            pfile = open(self.location+rid+'/recover/'+i, 'w')
            pfile.write(pars_out[i])
            pfile.close()
        del self.jobs['recover']
        run_par2(['par2', 'r', self.location+rid+'/recover/'+s['name']])
        infile = open(self.location+rid+'/recover/'+s['name'])
        for i in range(len(s['articles'])):
            data = infile.read(s['articles'][i]['bytes'])
            arts_out[i] = data
            print s['articles'][i]['bytes'], len(data)
            self.store(rid, segments, [seg, i], data, True)
        return arts_out[path[1]]
        shutil.rmtree(self.location+rid+'/recover/')

    def memgrab(self, rid, segments, path):
        messageid = segments[path[0]]['articles'][path[1]]['article']
        if not messageid in self.hashcache:
            return None
        if self.hashcache[messageid][0] == False:
            data = self.hashcache[messageid][1].get()
            self.store(rid, segments, path, data)
            return data
        return self.hashcache[messageid][1]
    
    def hddgrab(self, rid, segments, path):
        mem = self.memgrab(rid, segments, path)
        if mem:
            return mem
        messageid = segments[path[0]]['articles'][path[1]]['article']
        if not os.path.exists(self.location+rid+'/'):
            os.mkdir(self.location+rid+'/')
        if os.path.exists(self.location+rid+'/'+messageid):
            data = open(self.location+rid+'/'+messageid).read()
            self.memstore(rid, segments, path, data)
            return data
        return None

    def memstore(self, rid, segments, path, data, force=False):
        messageid = segments[path[0]]['articles'][path[1]]['article']
        if not messageid in self.hashcache or force:
            self.hashcache[messageid] = (True, data)
            self.rollcache.append(messageid)
            if len(self.rollcache) > 10:
                rem = self.rollcache.pop(0)
                del self.hashcache[rem]
    
    def hddstore(self, rid, segments, path, data, force=False):
        messageid = segments[path[0]]['articles'][path[1]]['article']
        self.memstore(rid, segments, path, data)
        if not os.path.exists(self.location+rid+'/'):
            os.mkdir(self.location+rid+'/')
        if not os.path.exists(self.location+rid+'/'+messageid) or force:
            open(self.location+rid+'/'+messageid,'w').write(data)

def run_par2(args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE,\
                         stderr=subprocess.STDOUT)
    fcntl.fcntl(p.stdout, fcntl.F_SETFL, os.O_NONBLOCK)
    while True:
        gsocket.wait_read(p.stdout.fileno())
        d = p.stdout.read(2048)
        if d == '':
            break
        print d
    p.stdout.close()

debug_decode = None
class DecodeLayer:
    def __init__(self, queue):
        self.queue = queue
    
    def get_article(self, messageid):
        global debug_decode
        a = gevent.event.AsyncResult()
        self.queue.put((messageid, a))
        result, data = a.get()
        if result:
            data = data[1]
        else:
            raise Exception, str(data)
        if data[:7] == '=ybegin':
            data = data[data.find('\r\n')+2:]
        if data[:6] == '=ypart':
            data = data[data.find('\r\n')+2:]
        if data.rfind('=yend') != -1:
            data = data[:data.rfind('\r\n')]
        data = data.replace('\r\n..','\r\n.')
        data, crc, _ = _yenc.decode_string(data)
        return data, crc

class UpstreamNNTP:
    def __init__(self, server, username=None, password=None, port=-1, ssl=False):
        self.server = server
        self.username = username
        self.password = password
        self.port = port
        if port == -1:
            self.port = 119 if ssl == False else 563
        self.ssl = ssl
        self.connected = False
    
    def connect(self):
        if self.connected:
            raise Exception, "Already Connected"
        if self.ssl:
            self.psock = socket.socket()
            self.sock = ssl.wrap_socket(self.psock)
        else:
            self.sock = socket.socket()
        self.sock.connect((self.server, self.port))
        result = self.sock.recv(1024)
        if result[:3] != '200':
            raise Exception, 'Server not accepting connection'
        if self.username:
            self.sock.send('authinfo user %s\r\n' % self.username)
            result = self.sock.recv(1024)
            if result[:3] == '381': # PASS required
                if not self.password:
                    raise Exception, "Password required"
                self.sock.send('authinfo pass %s\r\n' % self.password)
                result = self.sock.recv(1024)
                if result[:3] != '281':
                    raise Exception, 'NNTP Login Incorrect'
        self.connected = True
        return self

    def post(self, data):
        if not self.connected:
            raise Exception, "Not Connected"
        self.sock.send("POST\r\n")
        self.sock.recv(16384)
        while len(data) > 0:
            sent = self.sock.send(data)
            data = data[sent:]
        self.sock.send("\r\n.\r\n")
        result = self.sock.recv(16384)
        if result[:3] == '441':
            raise Exception, "NNTP Error %s" % repr(result)
        return result[:-2]

    def article(self, message_id):
        global bytes_down
        if not self.connected:
            raise Exception, "Not Connected"
        self.sock.send("ARTICLE %s\r\n" % message_id)
        output = self.sock.recv(16384)
        if output[:3] == '430':
            raise IOError, "No such article"
        elif output[:3] == '412':
            raise Exception, "Not in a newsgroup"
        elif output[:1] == '4':
            raise Exception, output
        if not output[-5:] == '\r\n.\r\n':
            while True:
                data = self.sock.recv(16384)
                bytes_down += len(data)
                output += data
                if output[-5:] == '\r\n.\r\n': break
        output = output[:-5]
        rheaders, article = output.split('\r\n\r\n',1)
        headers = rheaders.split('\r\n')
        head = dict((k,v) for k,v in (a.split(': ', 1) for a in headers[1:]))
        return head, article

    def date(self):
        if not self.connected:
            raise Exception, "Not Connected"
        self.sock.send("DATE\r\n")
        result = self.sock.recv(1024)
        return result[:-2]

    def quit(self):
        if not self.connected:
            raise Exception, "Not Connected"
        self.sock.send("QUIT\r\n")
        self.sock.recv(1024)
        self.sock.close()
        self.connected = False

river_queue = queue.PriorityQueue()
river_pool = []
def init_bg_queue():
    global river_queue, river_pool
    logging.info('spawning background workers')
    for _ in xrange(ci('usenet','connections')):
        g = gevent.Greenlet(nntp_conn_thread)
        river_pool.append(g)
        g.start()
    logging.info("background queue created")
        
def nntp_test(server, port, ssl, username, password):
    orig_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        n = UpstreamNNTP(server, username, password, port, ssl)
        n.connect()
        socket.setdefaulttimeout(orig_timeout)
        return True, 'Success!'
    except Exception, e:
        socket.setdefaulttimeout(orig_timeout)
        return False, e.args[-1]

def nntp_conn_thread():
    global river_queue
    logging.info("Starting new NNTP thread")
    while True:
        try:
            n = UpstreamNNTP(c('usenet', 'server'), c('usenet','username'), c('usenet','password'), ci('usenet','port'), cb('usenet','ssl'))
            n.connect()
            logging.info("NNTP thread %s started" % n)
        except Exception, e:
            logging.info("NNTP thread failed! %s" % e.args[-1])
            return False, e.args[-1]
        while True:
            try:
                messageid, finish = river_queue.get(True, 60)
                logging.info("%s downloading %s" % (n, messageid))
                try:
                    article = n.article('<'+messageid+'>')
                    logging.info("%s finished downloading %s" % (n, messageid))
                    finish.set((True, article))
                except IOError, e:
                    logging.info("%s could not download %s: Article not found" % (n, messageid))
                    if config.has_section('usenet-backup'):
                        nb = UpstreamNNTP(c('usenet-backup', 'server'), c('usenet-backup','username'), c('usenet-backup','password'), ci('usenet-backup','port'), cb('usenet-backup','ssl'))
                        logging.info("%s starting backup thread %s" % (n, nb))
                        nb.connect()
                        try:
                            article = nb.article('<'+messageid+'>')
                        except IOError, e:
                            logging.info("backup %s could not download %s: Article not found" % (nb, messageid))
                            finish.set((False, e))
                        except Exception, e:
                            logging.info("backup %s could not download %s: %s" % (nb, messageid, e))
                            finish.set((False, e))
                except Exception, e:
                    logging.info("%s could not download %s: %s" % (n, messageid, e))
                    finish.set((False, e))
            except gevent.queue.Empty:
                try:
                    n.date()
                    logging.debug("NNTP thread %s performed a keepalive" % n)
                except:
                    logging.info("NNTP thread %s timed out" % n)
                    break

def patch_handle_one_response(self):
    global rivers
    path = self.path.split('/')
    if len(path) == 4 and path[1] == 'play':
        addr, port = self.client_address
        self.environ['webriver.remote_port'] = str(port)
        if not addr in streams:
            streams[addr] = {}
        if not addr in streamsbw:
            streamsbw[addr] = {}
        streams[addr][str(port)] = {'link': 0, 'rid': path[2]}
        rivers[path[2]]['isDownloading'] = True
        rivers[path[2]]['update'] += 1
        rivers[path[2]]['active'][str(port)] = True
        if len(rivers[path[2]]['active']) > 1:
            rivers[path[2]]['progress'] = 99
        streamsbw[addr][str(port)] = {'bytes': 0, 'last': time.time()}
    return self.actual_handle_one_response()
    
WSGIHandler.actual_handle_one_response = WSGIHandler.handle_one_response
WSGIHandler.handle_one_response = patch_handle_one_response

def patch_write(self, data):
    try:
        return self.actual_write(data)
    except socket.error, ex:
        path = self.path.split('/')
        if len(path) == 4 and path[1] == 'play':
            addr, port = self.client_address
            port = str(port)
            print "SOCKET CLOSED ON STREAM"
            del rivers[path[2]]['active'][str(port)]
            if len(rivers[path[2]]['active']) == 0:
                rivers[path[2]]['isDownloading'] = False
                if rivers[path[2]]['isRecording']:
                    rivers[path[2]]['progress'] = int(float(rivers[path[2]]['recorded']) / float(rivers[path[2]]['total']) * 100.0)
                else:
                    rivers[path[2]]['progress'] = 0
                rivers[path[2]]['update'] += 1
            if addr in streams:
                if port in streams[addr]:
                    del streams[addr][port]
                if len(streams[addr]) == 0:
                    del streams[addr]
        raise

WSGIHandler.actual_write = WSGIHandler.write
WSGIHandler.write = patch_write

def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

if __name__ == '__main__':
    par = which('par2')
    if par == None:
        raise Exception, "Par2 not found in path. It is required for WebRiver to function"
    else:
        print "Found par2 at", par
    logging.info('Loading configuration...')
    load_config()
    if is_configured():
        init_bg_queue()
        load_metadata()
        dlayer = DecodeLayer(river_queue)
        clayer = CacheLayer(dlayer)
        flayer = FileLayer(clayer)
        gevent.spawn(timer_calculate_bandwidth)
    print "Ready."
    try:
        WSGIServer(('',5000),app).serve_forever()
    except:
        save_metadata()