var session;
var pollSpeed = 1000;
var pollTimeout;

var main = $('title').text() == 'WebRiver';
var pvr = false;
var rivers = {};

$(function () {
    if (main) {
        $('.tabs a:last').tab('show');
        $.getJSON('/init_state', initState);
        $('#rivers tr:first').after('<tr id="river-loading"><td colspan="4">Loading Rivers...</td></tr>');
        $('#upload-fromfile').on('hidden', uploadHidden);
        $('#upload-fromurl').on('hidden', urlHidden);
        $('#upload-fromurl').on('shown', urlShown);
        $('#do-upload-fromfile').click(autoFile);
    }
    $('#configform').submit(validate_configuration);
})

function initState(data, textStatus) {
    if ('not_configured' in data) {
        window.location.href = '/cfg';
        return;
    }
    if ('pvr' in data) {
        pvr = true;
    }
    else {
        pvr = false;
    }
    $('#river-loading').remove();
    session = data['session'];
    for (i in data['rivers']) {
        var r = data['rivers'][i];
        rivers[i] = {'name': r['name'], 'filename': r['filename']};
        newRiverRow(i, r['name'], r['filename'], r['progress'], r['isDownloading'], r['isRecording'], r['nfo']);
    }
    for (i in data['logs']) {
        var l = data['logs'][i];
        newLogRow(i, l['type'], l['message']);
    }
    updateState();
    $('#sub-add-subscribe-input').typeahead(source=data['categories']);
}

function updateState() {
    pollTimeout = setTimeout('updateState()', pollSpeed);
    $.getJSON('/update_state?session='+session, updateState2);
}

function humanBytes(bytes) {
    if (bytes > 1000000000000) {
        var output = (bytes/1000000000000.0).toFixed(2) + ' T';
    } else
    if (bytes > 1000000000) {
        var output = (bytes/1000000000.0).toFixed(2) + ' G';
    } else
    if (bytes > 1000000) {
        var output = (bytes/1000000.0).toFixed(2) + ' M';
    } else
    if (bytes > 1000) {
        var output = (bytes/1000.0).toFixed(2) + ' K';
    }
    else {
        var output = bytes.toString() + ' ';
    }
    return output+'B';
}

function updateState2(data, textStatus) {
    if ('not_configured' in data) {
        window.location.href = '/cfg';
        return;
    }
    if ('session' in data) {
        session = data['session'];
        clearRivers();
        clearLogs();
        if ('pvr' in data) {
            pvr = true;
        }
        else {
            pvr = false;
        }
        for (i in data['rivers']) {
            var r = data['rivers'][i];
            rivers[i] = {'name': r['name'], 'filename': r['filename']};
            newRiverRow(i, r['name'], r['filename'], r['progress'], r['isDownloading'], r['isRecording'], r['nfo']);
        }
        for (i in data['logs']) {
            var l = data['logs'][i];
            newLogRow(i, l['type'], l['message']);
        }
    }
    else {
        if ('rivers' in data) {
            if ('new' in data['rivers']) {
                for (i in data['rivers']['new']) {
                    var r = data['rivers']['new'][i];
                    rivers[i] = {'name': r['name'], 'filename': r['filename']};
                    newRiverRow(i, r['name'], r['filename'], r['progress'], r['isDownloading'], r['isRecording'], r['nfo']);
                }
            }
            if ('update' in data['rivers']) {
                for (i in data['rivers']['update']) {
                    var r = data['rivers']['update'][i];
                    updateRiverRow(i, r['progress'], r['isDownloading'], r['isRecording']);
                }
            }
            if ('delete' in data['rivers']) {
                for (i in data['rivers']['delete']) {
                    delete rivers[i];
                    deleteRiverRow(data['rivers']['delete'][i]);
                }
            }
        }
        if ('logs' in data) {
            if ('new' in data['logs']) {
                for (i in data['logs']['new']) {
                    var l = data['logs']['new'][i];
                    newLogRow(i, l['type'],l['message']);
                }
            }
            if ('delete' in data['logs']) {
                for (i in data['logs']['delete']) {
                    deleteLogRow(i);
                }
            }
        }
    }
    var downlink = data['download']['downlink'];
    var uplink = data['download']['uplink'];
    var output = '<i class="icon-white icon-chevron-down"></i> ';
    output += humanBytes(downlink) + '/s - <i class="icon-white icon-chevron-up"></i> ';
    output += humanBytes(uplink) + '/s';
    outlinks = ''
    if ($.isEmptyObject(data['download']['ips'])) {
        outlinks = '<p>There are currently no links.</p>';
    }
    else {
        for (i in data['download']['ips']) {
            outlinks += '<h3>' + i + '</h3>';
            outlinks += '<table class="table table-striped table-bordered table-condensed"><tr><th>Name</th><th>Downlink</th></tr>';
            for (j in data['download']['ips'][i]) {
                var r = data['download']['ips'][i][j]['rid'];
                var l = data['download']['ips'][i][j]['link'];
                outlinks += '<td>' + rivers[r]['name'] + '</td><td>' + humanBytes(l) + '/s</td><tr>';
            }
            outlinks += '</table><br />';
        }
    }
    $('#link-details-body').html(outlinks);
    $('#link').html(output);
}

function autoFile(evt) {
    $('#river-file').click();
    evt.preventDefault();
}

function doOptions() {
    $.getJSON('/get_config', optionsPage);
}

function optionsPage(data) {
    if ('ub' in data) {
        $('#unb-enabled').prop('checked', true);
        if ('username' in data['ub'])
            $('#unb-username').attr('value',data['ub']['username']);
        if ('password' in data['ub'])
            $('#unb-password').attr('value','WR_DO_NOT_CHANGE_THIS_PASSWORD_UB');
        
        $('#unb-server').attr('value',data['ub']['server']);
        $('#unb-port').attr('value',data['ub']['port']);
        if (data['ub']['ssl'] == 'on')
            $('#unb-ssl').prop('checked', true);
        $('#unb-connect').attr('value',data['ub']['connect']);
        
        $('#unb-server').removeAttr('disabled');
        $('#unb-password').removeAttr('disabled');
        $('#unb-username').removeAttr('disabled');
        $('#unb-port').removeAttr('disabled');
        $('#unb-ssl').removeAttr('disabled');
        $('#unb-connect').removeAttr('disabled');
        $('#unb-test').removeAttr('disabled');
    }
    
    if ('username' in data['u'])
        $('#un-username').attr('value',data['u']['username']);
    if ('password' in data['u'])
        $('#un-password').attr('value','WR_DO_NOT_CHANGE_THIS_PASSWORD_U');
    
    $('#un-server').attr('value',data['u']['server']);
    $('#un-port').attr('value',data['u']['port']);
    if (data['u']['ssl'] == 'on')
            $('#un-ssl').prop('checked', true);
    $('#un-connect').attr('value',data['u']['connect']);
    
    if (data['wr']['username']) {
        $('#wr-auth').prop('checked', true);
        $('#wr-username').removeAttr('disabled');
        $('#wr-password').removeAttr('disabled');
        $('#wr-username').attr('value',data['wr']['username']);
        $('#wr-password').attr('value','WR_DO_NOT_CHANGE_THIS_PASSWORD_WR');
    }
    if (data['wr']['pvr'] == 'on') {
            $('#wr-pvr').prop('checked', true);
            $('#wr-auto').removeAttr('disabled');
            $('#wr-pre').removeAttr('disabled');
    }
    if (data['wr']['auto'] == 'on')
            $('#wr-auto').prop('checked', true);
    if (data['wr']['pre'] == 'on')
            $('#wr-pre').prop('checked', true);
}

function setPoll(speed) {
    $('#poll').html('Refresh: '+speed.toString()+'s <b class="caret"></b>');
    pollSpeed = speed*1000;
    clearTimeout(pollTimeout);
    updateState();
}

function onSubTextChange() {
    var s = $('#sub-add-subscribe-input').val()
    if (s[s.length-1] == '.') {
        $.getJSON('/sub_complete', {'s': s}, subTextChange);
    }
}

function subTextChange(data, textStatus) {
    $('#sub-add-subscribe-input').typeahead(source=data);
}

function doRecord(id) {
    $.getJSON('/record_river?row='+id, doRecord2);
}

function stopRecord(id) {
    $.getJSON('/record_river_stop?row='+id, doRecord2);
}

function doRecord2(data) {
    if (data == false) {
        alert('Could not record river - try refreshing WebRiver');
        return;
    }
    updateRiverRow(data['id'], data['progress'], data['isDownloading'], data['isRecording']);
}

function doUpload() {
    var form = new FormData(document.getElementById('river-upload'));
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/add_upload', true);
    xhr.addEventListener('load', doUpload2, false);
    xhr.send(form);
    $('#river-upload-body').html('Please wait, uploading...');
    $('#river-upload-footer').html('');
    //$('#upload-fromfile').hide();
}

function doUpload2(evt) {
    var data = JSON.parse(evt.target.responseText);
    doChoose(data, 'upload');
}

function uploadLoadCheckRow() {
    if ($('input.upload-load-check-row').is(':checked'))
        $('#upload-load-check').prop('checked', true);
    else
        $('#upload-load-check').prop('checked', false);
}

function uploadLoadCheck() {
    if ($('#upload-load-check').is(':checked')) {
        $('input.upload-load-check-row').prop('checked', true);
    } else {
        $('input.upload-load-check-row').prop('checked', false);
    }
}

function uploadSubmit() {
    var out = [];
    var rows = $('input.upload-load-check-row').toArray();
    for (i in rows) {
        var j = rows[i];
        var k = j['id'].substr(21);
        out.push(parseInt(k));
        newRiverRow(k, rivers[k]['name'], rivers[k]['filename'], 0, false, false, rivers[k]['nfo']);
    }
    doAdd(out, which);
}

function doAdd(out, which) {
    if (which == 'upload') which = 'file';
    $.post('/add_rivers?session='+session, {'add': JSON.stringify(out)}, doAdd2, 'json');
    $('#upload-from'+which).modal('hide');
}

function doAdd2(data) {
    for (i in data) {
        updateRiverRow(data[i], data['progress'], data['isDownloading'], data['isRecording'], data['nfo']);
    }
}

function uploadHidden() {
    $('#river-upload-header').html('<a class=\"close\" data-dismiss=\"modal\">×</a><h3>Upload .river from file</h3>');
    $('#river-upload-body').html('<input type=\"file\" class=\"input-xlarge\" name=\"river\" id=\"river-file\" />');
    $('#river-upload-footer').html('<button type=\"button\" class=\"btn btn-primary\" onclick=\"doUpload()\">Upload</button><a href=\"#\" class=\"btn\" data-dismiss=\"modal\">Cancel</a>');
}

function doUrl() {
    $.post('/add_url', {'river': $('#river-url-input').val()}, doUrl2, 'json');
}

function doUrl2(data, textStatus) {
    if (data == false) {
        $('#river-url-body').html('Error');
        $('#river-url-body').html('Sorry, an error occurred while trying to use this rlink');
        return;
    }
    doChoose(data, 'url');
}

function doChoose(data, which) {
    if (data['files'].length == 1) {
        var file = data['files'][0];
        doAdd([file['id']], which);
        rivers[file['id']] = {'name': file['name'], 'filename': file['filename']};
        newRiverRow(file['id'], file['name'], file['filename'], 0, false, false, file['nfo']);
    }
    else {
        $('#river-'+which+'-header h3').text('Select files from ' + data['name']);
        var out = '<table id=\"upload-load-table\" class=\"table table-bordered table-condensed table-striped\">'+
                '<tr><th><input onchange=\"uploadLoadCheck()\" id=\"upload-load-check\" type=\"checkbox\" checked></th><th>Name</th><th>Size</th></tr>';
        for (i in data['files']) {
            var f = data['files'][i];
            out += '<tr><td><input class=\"upload-load-check-row\" onchange=\"uploadLoadCheckRow()\" '+
                'id=\"upload-load-check-row'+f['id']+'\" type=\"checkbox\" checked></td><td id=\"upload-load-name-row'+f['id']+'\"></td>'+
                '<td>'+humanBytes(f['bytes'])+'</td></tr>';
            rivers[f['id']] = {'name': f['name'], 'filename': f['filename'], 'bytes': f['bytes'], 'description': f['description']};
        }
        out += '</table>';
        $('#river-'+which+'-body').html(out);
        for (i in data['files']) {
            var f = data['files'][i];
            if (f['name'] == f['filename'])
                $('#upload-load-name-row'+f['id']).text(f['name']);
            else
                $('#upload-load-name-row'+f['id']).text(f['name']+' ('+f['filename']+')');
        }
        $('#river-'+which+'-footer').html('<button onclick=\"uploadSubmit()\" type=\"button\" class=\"btn btn-primary\">Add</button>');
    }
}

function urlHidden() {
    $('#river-url-header').html('<a class=\"close\" data-dismiss=\"modal\">×</a><h3>Upload .river from URL</h3>');
    $('#river-url-body').html('<input type=\"text\" id=\"river-url-input\" class=\"input-xlarge\" name=\"river\"/>');
    $('#river-url-footer').html('<button type=\"button\" class=\"btn btn-primary\" onclick=\"doUrl()\">Upload</button><a href=\"#\" class=\"btn\" data-dismiss=\"modal\">Cancel</a>');
}

function urlShown() {
    $('#river-url-input').focus();
}

function newRiverRow(id, name, filename, progress, isDownloading, isRecording, nfo) {
    if ($('#river-row'+id.toString()).length > 0) return;
    var statusString = (progress == 100?'Complete':(isDownloading?'Streaming':(isRecording?'Recording':'Idle')))+' - '+progress.toString()+'%';
    var statusClass = 'progress progress-striped '+(progress.toString() == 100?'progress-success':(isDownloading?'active':(isRecording?'progress-warning active':'progress-danger')));
    var recordButton = '<a id=\"river-row'+id.toString()+'-record\" class=\"btn btn-info btn-mini\" onclick=\"'+(isRecording?'stop':'do')+'Record('+id.toString()+')\">'+(isRecording?'Stop':'Record')+'</a>';
    var nfoButton = ' <a href=\"/nfo/'+id.toString()+'\" class=\"btn btn-inverse btn-mini\">NFO</a>'
    var data = '<tr id=\"river-row'+id.toString()+'\"><td>'+name+'</td>'+
                '<td style=\"white-space:nowrap\" height=\"1\" id=\"river-row'+id.toString()+'-status\">'+statusString+'</td>'+
                '<td><div id=\"river-row'+id.toString()+'-class\" class=\"'+statusClass+'\" style=\"margin-bottom:0px\">'+
                '<div id=\"river-row'+id.toString()+'-progress\" class=\"bar\" style=\"width:'+progress.toString()+'%\"></div></div></td>'+
                '<td style=\"white-space:nowrap\"><a class=\"btn btn-primary btn-mini\" href=\"/play/'+id.toString()+'/'+filename+'\">Download</a> '+
                (pvr ? recordButton : '') +
                (nfo ? nfoButton : '') +
                '</td><td width="1"><a class="close" onclick="doDeleteRiverRow('+id+')">×</a></td></tr>';
    $('#rivers tr:first').after(data);
}

function updateRiverRow(id, progress, isDownloading, isRecording) {
    if ($('#river-row'+id.toString()).length == 0) return;
    var statusString = (progress == 100?'Complete':(isDownloading?'Streaming':(isRecording?'Recording':'Idle')))+' - '+progress.toString()+'%';
    var statusClass = 'progress progress-striped '+(progress.toString() == 100?'progress-success':(isDownloading?'active':(isRecording?'progress-warning active':'progress-danger')));
    var recordButton = (isRecording?'Stop':'Record');
    var recordClick = (isRecording?'stop':'do');
    $('#river-row'+id.toString()+'-status').html(statusString);
    $('#river-row'+id.toString()+'-class').attr('class',statusClass);
    $('#river-row'+id.toString()+'-progress').css('width',progress.toString()+'%');
    $('#river-row'+id.toString()+'-record').html(recordButton);
    $('#river-row'+id.toString()+'-record').attr('onclick', recordClick+'Record('+id.toString()+')');
}

function deleteRiverRow(id) {
    if ($('#river-row'+id.toString()).length == 0) return;
    $('#river-row'+id.toString()).remove();
}

function newLogRow(id, type, message) {
    if ($('#log-row'+id.toString()).length > 0) return;
    var color = 'FFFFFF';
    if (type == 'Warning') color='FFEBCD';
    else if (type == 'Info') color='D7EBFF';
    else if (type == 'Error') color='FFD7D7';
    var data = '<tr bgcolor=\"#'+color+'\" id=\"log-row'+id.toString()+'\"><td>'+type+'</td><td>'+message+'</td><td><a class=\"close\" onclick=\"doDeleteLogRow('+id+')\">×</a></td>';
    $('#logs tr:first').after(data);
}

function deleteLogRow(id) {
    if ($('#log-row'+id.toString()).length == 0) return;
    $('#log-row'+id.toString()).remove();
}

function doDeleteLogRow(id) {
    deleteLogRow(id);
    $.getJSON('/delete_log_row?session='+session+'&row='+id);
}

function doDeleteRiverRow(id) {
    if (!pvr) {
        var answer = confirm('Are you sure you want to remove this river?\r\n');
    }
    else {
        var answer = confirm('Are you sure you want to remove this river?\r\nThis will remove all PVR\'d data.');
    }
    if (answer) {
        deleteRiverRow(id);
        delete rivers[id];
        $.getJSON('/delete_river?session='+session+'&row='+id);
        return;
    }
}

function doClearRivers() {
    if ($('#rivers tr').length == 1) return;
    if (!pvr) {
        var answer = confirm('Are you sure you want to clear all rivers?');
    }
    else {
        var answer = confirm('Are you sure you want to clear all rivers?\r\nThis will remove all PVR\'d data.');
    }
    if (answer) {
        $.getJSON('/clear_rivers?session='+session);
        clearRivers();
    }
}

function doClearLogs() {
    if ($('#logs tr').length == 1) return;
    var answer = confirm('Are you sure you want to clear all logs?');
    if (answer) {
        $.getJSON('/clear_logs?session='+session, doClearLogs2);
    }
}

function doClearLogs2(data, textStatus) {
    if (data == true)
        clearLogs();
    else
        alert('Could not clear logs. Try refreshing WebRiver');
}

function clearRivers() {
    $('#rivers').html('<tr><th>Name</th><th width=\"150\">Status</th><th width=\"250\">Progress</th><th width=\"1\">Actions</th><th width=\"1\"><a class="close" onclick="doClearRivers()">×</a></th></tr>');
}

function clearLogs() {
    $('#logs').html('<tr><th width=\"150\">Type</th><th>Message</th><th width=\"1\"><a class=\"close\" onclick=\"doClearLogs()\">×</a></th></tr>');
}

function test_server(w) {
    var testDest;
    if (w == 0) {
        testDest = '#tested';
        var server = $('#un-server').val();
        var username = $('#un-username').val();
        var password = $('#un-password').val();
        var port = $('#un-port').val();
        var ssl = $('#un-ssl').is(':checked');
    } else {
        testDest = '#btested';
        var server = $('#unb-server').val();
        var username = $('#unb-username').val();
        var password = $('#unb-password').val();
        var port = $('#unb-port').val();
        var ssl = $('#unb-ssl').is(':checked');
    }
    var toSend = {'server': server, 'username': username, 'password': password, 'port': port, 'ssl': ssl};
    $.getJSON('/test_connection', toSend, function(data) {
        if (data[0] == true) {
            $(testDest).attr('style', 'font-weight:bold;color:#0A0');
            $(testDest).html(data[1]);
        } else {
            $(testDest).attr('style', 'font-weight:bold;color:#A00');
            $(testDest).html(data[1]);
        }
    });
    $(testDest).attr('style', 'color:#00A');
    $(testDest).html('Please wait...');
}

function toggle_ssl(w) {
    if (w == 0) {
        if ($('#un-port').val() == '443') {
            $('#un-ssl').prop('checked', true);
        }
    } else {
        if ($('#unb-port').val() == '443') {
            $('#unb-ssl').prop('checked', true);
        }
    }
}

function toggle_port(w) {
    if (w == 0) {
        if ($('#un-ssl').is(':checked')) {
            if ($('#un-port').val() == '119' || $('#un-port').val().length == 0) {
                $('#un-port').val('563');
            }
        } else {
            if ($('#un-port').val() == '563' || $('#un-port').val().length == 0) {
                $('#un-port').val('119');
            }
        }
    } else {
        if ($('#unb-ssl').is(':checked')) {
            if ($('#unb-port').val() == '119' || $('#unb-port').val().length == 0) {
                $('#unb-port').val('563');
            }
        } else {
            if ($('#unb-port').val() == '563' || $('#unb-port').val().length == 0) {
                $('#unb-port').val('119');
            }
        }
    }
}

function toggle_auth() {
    if ($('#wr-auth').is(':checked')) {
        $('#wr-username').removeAttr('disabled');
        $('#wr-password').removeAttr('disabled');
    }
    else {
        $('#wr-username').prop('disabled', true);
        $('#wr-password').prop('disabled', true);
        
    }
}

function toggle_pvr() {
    if ($('#wr-pvr').is(':checked')) {
        $('#wr-auto').removeAttr('disabled');
        $('#wr-pre').removeAttr('disabled');
    }
    else {
        $('#wr-auto').prop('disabled', true);
        $('#wr-pre').prop('disabled', true);
    }
}

function toggle_backup() {
    if ($('#unb-enabled').is(':checked')) {
        $('#unb-server').removeAttr('disabled');
        $('#unb-username').removeAttr('disabled');
        $('#unb-password').removeAttr('disabled');
        $('#unb-port').removeAttr('disabled');
        $('#unb-ssl').removeAttr('disabled');
        $('#unb-connect').removeAttr('disabled');
        $('#unb-test').removeAttr('disabled');
    } else {
        $('#unb-server').attr('disabled', 'disabled');
        $('#unb-username').attr('disabled', 'disabled');
        $('#unb-password').attr('disabled', 'disabled');
        $('#unb-port').attr('disabled', 'disabled');
        $('#unb-ssl').attr('disabled', 'disabled');
        $('#unb-connect').attr('disabled', 'disabled');
        $('#unb-test').attr('disabled', 'disabled');
    }
}

function validate_configuration() {
    var failed=false;
    if ($('#un-connect').val().length == 0) {
        $('#tested').attr('style', 'font-weight:bold;color:#A00');
        $('#tested').html('Connections cannot be blank');
        failed=true;
    }
    if ($('#un-port').val().length == 0) {
        $('#tested').attr('style', 'font-weight:bold;color:#A00');
        $('#tested').html('Port cannot be blank');
        failed=true;
    }
    if ($('#un-server').val().length == 0) {
        $('#tested').attr('style', 'font-weight:bold;color:#A00');
        $('#tested').html('Server cannot be blank');
        failed=true;
    }
    if ($('#unb-enabled').is(':checked')) {
        if ($('#unb-connect').val().length == 0) {
            $('#btested').attr('style', 'font-weight:bold;color:#A00');
            $('#btested').html('Connections cannot be blank');
            failed=true;
        }
        if ($('#unb-port').val().length == 0) {
            $('#btested').attr('style', 'font-weight:bold;color:#A00');
            $('#btested').html('Port cannot be blank');
            failed=true;
        }
        if ($('#unb-server').val().length == 0) {
            $('#btested').attr('style', 'font-weight:bold;color:#A00');
            $('#btested').html('Server cannot be blank');
            failed=true;
        }
    }
    if (main)
        if (!failed) {
            var form = new FormData(document.getElementById('configform'));
            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/configure', true);
            xhr.send(form);
            alert('Saved. Any server changes require WebRiver to be restarted.');
            return false;
        }
    return !failed;
}

