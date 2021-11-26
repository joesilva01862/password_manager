// global vars
var enc_bit_size = 128;

function getKeys() {
  var request = new XMLHttpRequest()
  request.open('GET', 'http://192.168.4.1/getkeys', true)
  request.onload = function () {
    // Begin accessing JSON data here
    var json = JSON.parse(this.response)
    
    if (request.status >= 200 && request.status < 400) {
        if (json.user.status == 'loggedout') {
            document.location.href = '/login';
            return;
        }
        
        // get the element id
        var dataarea = document.getElementById('dataarea');
        
        // build table
        var content = '';
        for (var i=0; i<json.keys.length; i++) {
            content += decrypt(json.keys[i]) + '\n';
        }    

        // update the div content
        dataarea.innerHTML = content;
    } 
    else {
        alert('Error invoking tracking API')
    }
  }    
  request.send();
}


function getKeysAndValues() {
  var request = new XMLHttpRequest()
  request.open('GET', 'http://192.168.4.1/getvalues', true)
  
  request.onload = function () {
    // Begin accessing JSON data here
    var json = JSON.parse(this.response);
    
    if (request.status >= 200 && request.status < 400) {
        if (json.user.status == 'loggedout') {
            document.location.href = '/login';
            return;
        }
        
        // populate table
        populateTable(json);

        // get the element id
        var dataarea = document.getElementById('dataarea');
        
        // build table
        var content = '';
        for (var i=0; i<json.pairs.length; i++) {
            var key = decrypt(json.pairs[i].key);
            var value = decrypt(json.pairs[i].value);
            content += key + ' = ' + value + '\n';
        }    

        // update the div content
        dataarea.innerHTML = content;
    } 
    else {
        alert('Error invoking tracking API')
    }
      
  }    

  request.send();
}


function deleteKey(key) {
  var request = new XMLHttpRequest();
  request.open('POST', 'http://192.168.4.1/delkey');
  request.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
  var enc_text = encrypt(key);
  request.send(enc_text);
  
  request.onload = function () {
      if (request.status >= 200 && request.status < 400) {
         var json = JSON.parse(this.response);
         
         if (json.user.status == 'loggedout') {
            document.location.href = '/login';
            return;
         }
        
         alert('Id '+key+' successfully deleted from the device.');
         
         // update the screen after deletion
         getKeysAndValues();
      }
  }
}


function postKeysAndValues() {
  var request = new XMLHttpRequest()
  request.open('POST', 'http://192.168.4.1/savevalues')
  var pairsarr = [];
  var lines = document.getElementById("saveinput").value.split('\n');
  
  if (lines.length == 0) {
      return;
  }
  
  for(var i=0; i<lines.length; i++) {
     tokens = lines[i].split('=');
     
     if (tokens.length == 2) {
        var obj = new Object();
        obj.key = tokens[0].trim();
        obj.value = tokens[1].trim();
        pairsarr.push(obj);
     }
  }
  
  json = '{ "pairs": ' + JSON.stringify(pairsarr) + '}';
  request.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
  var enc_text = encrypt(json);
  request.send(enc_text);
  
  request.onload = function () {
      if (request.status >= 200 && request.status < 400) {
         var json = JSON.parse(this.response);
         if (json.user.status == 'loggedout') {
            document.location.href = '/login';
            return;
         }
        
         alert('Data successfully saved on the device.');
         document.getElementById("saveinput").value = '';
      }
  }
   
}

/*
// take base64 string, decrypt it, and return plain text
function decrypt(enc_text) {
    //var decoded_text = CryptoJS.enc.Base64.parse(enc_text);
    var decoded_key = atob(localStorage.getItem('enckey'));
    var decoded_iv  = atob(localStorage.getItem('iv'));

    var decrypted = CryptoJS.AES.decrypt(
        enc_text,
        decoded_key,
      {
        iv: decoded_iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }
    );

    plain_text = decrypted.toString(CryptoJS.enc.Utf8);
    return plain_text;
}
*/

function decrypt(enc_text) {
    var decoded_key = atob(localStorage.getItem('enckey'));
    var decoded_iv  = atob(localStorage.getItem('iv'));
    var iv = CryptoJS.enc.Utf8.parse(decoded_iv);
    key = CryptoJS.enc.Utf8.parse(decoded_key);
    var decrypted =  CryptoJS.AES.decrypt(enc_text, key, { iv: iv, mode: CryptoJS.mode.CBC});
    return decrypted.toString(CryptoJS.enc.Utf8); 
}


// encrypt plain text and return base64 string
function encrypt(plain_text) {
    var enckey = atob(localStorage.getItem('enckey'));
    var iv     = atob(localStorage.getItem('iv'));
    var parsedKey = CryptoJS.enc.Utf8.parse(enckey);
    var parsedIv = CryptoJS.enc.Utf8.parse(iv)
    var encrypted = CryptoJS.AES.encrypt(plain_text, parsedKey, { iv: parsedIv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7});
    encryptedStr = encrypted.toString();
    return encryptedStr;
}

function addClickEvents() {
    var a = document.getElementsByClassName('greenbtn');

    for (var i = 0; i < a.length; i++) {
      a[i].addEventListener('click', function() {
        var b = this.parentNode.parentNode.cells[1].textContent;
        copyToClipboard(b);
      });
    }
    
}

function copyToClipboard(text) {
    var dummy = document.createElement("textarea");
    document.body.appendChild(dummy);
    dummy.value = text;
    dummy.select();
    dummy.setSelectionRange(0, 99999); // For mobile devices
    document.execCommand("copy");
    document.body.removeChild(dummy);
}    

function hintBoxChecked() {
    // Get the checkbox
    var checkBox = document.getElementById("hintBoxId");
    // Get the output text
    var text = document.getElementById("hintTextId");
  
    // If the checkbox is checked, display the output text
    if (checkBox.checked == true){
      text.style.display = "block";
    } else {
      text.style.display = "none";
    }
} 

function populateTable(json) {
    var table = document.getElementById('passtable');
    var rowCount = table.rows.length;
    
    for (var x=rowCount-1; x>0; x--) {
        table.deleteRow(x);
    }

    for (var i=0; i<json.pairs.length; i++) {
        var row = table.insertRow( -1 ); // -1 is insert as last  
        var cell0 = row.insertCell( - 1 ); // -1 is insert as last            
        var cell1 = row.insertCell( - 1 ); // -1 is insert as last            
        var cell2 = row.insertCell( - 1 ); // -1 is insert as last   
        var keytext = decrypt(json.pairs[i].key);
        var valuetext = decrypt(json.pairs[i].value);
        cell0.innerHTML = keytext;
        cell1.innerHTML = valuetext;
        keyStr = "'"+keytext+"'";
        var btn = '<button class="tablebtn redbtn" onClick="deleteKey(' +keyStr+ ');">delete</button> <button class="tablebtn greenbtn">copy</button>';
        cell2.innerHTML = btn;
    }    

    addClickEvents();
}

function getCookie(name) {
    var value = "; " + document.cookie;
    var parts = value.split("; " + name + "=");
    if (parts.length == 2)
        return parts.pop().split(";").shift();
}

function onLoad() {
    document.getElementById("hintBoxId").checked = false;
    var hint = getCookie('hintText');
    document.getElementById('hintTextId').innerHTML = hint;
}

function changePassHint() {
    var request = new XMLHttpRequest()
    request.open('POST', 'http://192.168.4.1/chghint');
    var curPass = document.getElementById('curpasshintid').value.trim();
    var passHint = document.getElementById('passwordhintid').value.trim();;
    var password = new Object();
    if ( curPass == '' || passHint == '') {
        alert('Neither password nor password hint can be blank');
        return;        
    }
    password.current = curPass;
    password.hint = passHint;

    json = '{ "password": ' + JSON.stringify(password) + '}';
    var enc_text = encrypt(json);
    request.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
    request.send(enc_text);
   
    request.onload = function () {
        if (request.status == 200) {
           var json = JSON.parse(this.response);
           if (json.user.status == 'loggedout') {
              document.location.href = '/login';
              return;
           }
            
           if (json.user.status == 'error') {
              alert('Current password doesn\'t match.');
              return;
           }
           
           alert('Hint has succesfully changed.');
           document.location.href = '/';
        }
    }
    
}

function changePassword(url) {
  var request = new XMLHttpRequest()
  request.open('POST', 'http://192.168.4.1/' + url)
  var curPass;
  var newPass;
  var rptNewPass;
  var passHint = '';
  var ssidName = '';

  if (url == 'chgpass') {
      curPass = document.getElementById('curpassid').value.trim();
      newPass = document.getElementById('newpassid').value.trim();
      rptNewPass = document.getElementById('rptnewpassid').value.trim();
      passHint = document.getElementById('passhintid').value.trim();
  }
  else {
      curPass = document.getElementById('curssidpassid').value.trim();
      newPass = document.getElementById('newssidpassid').value.trim();
      rptNewPass = document.getElementById('rptnewssidpassid').value.trim();
      ssidName = document.getElementById('newssidid').value.trim();
  }

  if (newPass != rptNewPass) {
      alert('New Password and Repeat New Password fields don\'t match.');
      return;
  }

  if (curPass === '' || newPass === '') {
      alert('Neither current password nor new password can be blank');
      return;
  }

  if ( newPass.length < 8) {
    alert('Password must have at least 8 characters');
    return; 
  }

  if (url == 'chgssidpass' && ssidName === '') {
      alert('SSID name cannot be blank');
      return;
  }

  if (url == 'chgpass' && passHint === '') {
    alert('Hint text cannot be blank');
    return;
  }

  var password = new Object();
  password.current = curPass;
  password.new = newPass;
  password.hint = passHint;
  password.newSSID = ssidName;

  json = '{ "password": ' + JSON.stringify(password) + '}';
  var enc_text = encrypt(json);
  request.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
  request.send(enc_text);
 
  request.onload = function () {
      if (request.status == 200) {
         var json = JSON.parse(this.response);
         if (json.user.status == 'loggedout') {
            document.location.href = '/login';
            return;
         }
          
         if (json.user.status == 'error') {
            alert('Current password doesn\'t match.');
            return;
         }
         
         alert('Password has succesfully changed.');

         if (url === 'chgpass') {
             document.location.href = '/login';
         }
         else {
             document.location.href = '/';
        }    
      }
  }

}

function setEncryptionKey() {
    var enckey = window.btoa(document.getElementById('enckey_id').value.trim());    
    var iv     = 'QkJCQkJCQkJCQkJCQkJCQg==' // BBBBBBBBBBBBBBBB;    
    localStorage.setItem('enckey', enckey);
    localStorage.setItem('iv', iv);
    var request = new XMLHttpRequest()
    request.open('GET', 'http://192.168.4.1/setenckey');
    request.send();
    request.onload = function () {
        if (request.status == 200) {
           var json = JSON.parse(this.response);

           if (json.user.status == 'error') {
               alert('Server error setting the encryption key');
               return;
           }
 
           document.location.href = '/login';
        }
    }
}


function sendLoginInfo() {
    if (!localStorage.getItem('enckey') || !localStorage.getItem('iv')) {
        alert('The encryption key procedure needs to be done first.');
        return;
    }

    var request = new XMLHttpRequest()
    request.open('POST', 'http://192.168.4.1/login')
    var login = new Object();
    login.username = document.getElementById('username').value.trim();
    login.password = document.getElementById('password').value.trim();

    if (login.username == '' || login.password == '') {
       alert('Both username and password needs to be provided');
       return;
    }
  
    // { "login": { "username":"John", "password":"bla bla bla"} }
    var text = '{ "login" : { "username" : "' + login.username + '", "password" : "' + login.password + '" } }'; 
    var enc_text = encrypt(text);
    request.setRequestHeader("Content-Type", "text/plain;charset=UTF-8");
    request.send(enc_text);

    request.onload = function () {
        if (request.status == 200) {
           var json = JSON.parse(this.response);
           if (json.user.status == 'error') {
              alert('Username or password doesn\'t match.');
              return;
           }

           // if there is no error, this will request index.html...
           document.location.href = '/';
        }
    }
  
}
  