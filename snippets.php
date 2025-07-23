<?php
// snippets.php

return [
    [
        'id' => 1,
        'title' => 'SQL Injection (PHP)',
        'code' => '<?php
include "db.php";
$username = $_GET["username"];
$password = $_GET["password"];
$query = "SELECT * FROM users WHERE username = \'$username\' AND password = \'$password\'";
$result = mysqli_query($conn, $query);
if ($row = mysqli_fetch_assoc($result)) {
    echo "Welcome, " . $row["username"];
} else {
    echo "Invalid login.";
}
?>',
        'vulnerability' => 'SQL Injection',
        'summary' => 'This code is vulnerable to SQL Injection because user input is directly embedded into the SQL query without sanitization or parameterization.',
        'resources' => [
            'https://owasp.org/www-community/attacks/SQL_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 2,
        'title' => 'Cross-Site Scripting (XSS) (PHP)',
        'code' => '<?php
$name = $_GET["name"];
$message = $_POST["message"];
file_put_contents("messages.txt", "$name: $message\n", FILE_APPEND);
$all = file_get_contents("messages.txt");
echo "<pre>$all</pre>";
?>',
        'vulnerability' => 'Cross-Site Scripting (XSS)',
        'summary' => 'This code is vulnerable to XSS because it outputs user input directly to the page without escaping.',
        'resources' => [
            'https://owasp.org/www-community/attacks/xss/',
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 3,
        'title' => 'Insecure Direct Object Reference (IDOR) (PHP)',
        'code' => '<?php
session_start();
$user = $_SESSION["user"];
$file = $_GET["file"];
$path = "/var/www/files/" . $file;
if (file_exists($path)) {
    readfile($path);
} else {
    echo "File not found.";
}
?>',
        'vulnerability' => 'Insecure Direct Object Reference (IDOR)',
        'summary' => 'This code is vulnerable to IDOR because it allows users to access arbitrary files by manipulating the file parameter.',
        'resources' => [
            'https://owasp.org/www-community/attacks/Direct_Object_Reference',
            'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 4,
        'title' => 'Cross-Site Scripting (XSS) (JavaScript)',
        'code' => '<!DOCTYPE html>
<html>
<body>
<form id="commentForm">
  <input id="name" placeholder="Name">
  <input id="comment" placeholder="Comment">
  <button type="submit">Post</button>
</form>
<div id="comments"></div>
<script>
document.getElementById("commentForm").onsubmit = function(e) {
  e.preventDefault();
  var name = document.getElementById("name").value;
  var comment = document.getElementById("comment").value;
  var html = "<b>" + name + ":</b> " + comment + "<br>";
  document.getElementById("comments").innerHTML += html;
};
</script>
</body>
</html>',
        'vulnerability' => 'Cross-Site Scripting (XSS)',
        'summary' => 'This JavaScript code is vulnerable to XSS because it writes untrusted data from the user directly into the DOM without sanitization.',
        'resources' => [
            'https://owasp.org/www-community/attacks/xss/',
            'https://developer.mozilla.org/en-US/docs/Web/Security/Types_of_attacks#Cross-site_scripting_(XSS)'
        ]
    ],
    [
        'id' => 5,
        'title' => 'Command Injection (Python)',
        'code' => 'import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/cat")
def cat_file():
    filename = request.args.get("filename")
    command = "cat " + filename
    stream = os.popen(command)
    output = stream.read()
    return f"<pre>{output}</pre>"

if __name__ == "__main__":
    app.run()',
        'vulnerability' => 'Command Injection',
        'summary' => 'This Python code is vulnerable to command injection because user input is concatenated into a shell command without validation or sanitization.',
        'resources' => [
            'https://owasp.org/www-community/attacks/Command_Injection',
            'https://cheatsheetseries.owasp.org/cheatsheets/Command_Injection_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 6,
        'title' => 'Insecure Deserialization (Java)',
        'code' => 'import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeserializeServlet extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            ObjectInputStream in = new ObjectInputStream(request.getInputStream());
            Object obj = in.readObject();
            response.getWriter().println("Deserialized: " + obj.toString());
        } catch (Exception e) {
            response.getWriter().println("Error: " + e.getMessage());
        }
    }
}',
        'vulnerability' => 'Insecure Deserialization',
        'summary' => 'This Java code is vulnerable to insecure deserialization because it deserializes untrusted data from the request, which can lead to remote code execution.',
        'resources' => [
            'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
            'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 7,
        'title' => 'Path Traversal (Node.js)',
        'code' => 'const http = require("http");
const fs = require("fs");
const url = require("url");

const server = http.createServer((req, res) => {
  const query = url.parse(req.url, true).query;
  const file = query.name;
  const filePath = "./uploads/" + file;
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end("File not found");
      return;
    }
    res.end(data);
  });
});
server.listen(3000);',
        'vulnerability' => 'Path Traversal',
        'summary' => 'This Node.js code is vulnerable to path traversal because it does not sanitize the file name, allowing attackers to access files outside the intended directory.',
        'resources' => [
            'https://owasp.org/www-community/attacks/Path_Traversal',
            'https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 8,
        'title' => 'Sensitive Data Exposure (Python Flask)',
        'code' => 'from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/debug")
def debug():
    secret = "supersecret"
    error = request.args.get("error")
    log = f"Error: {error} - Secret: {secret}"
    with open("debug.log", "a") as f:
        f.write(log + "\n")
    return log

if __name__ == "__main__":
    app.run()',
        'vulnerability' => 'Sensitive Data Exposure',
        'summary' => 'This Flask endpoint exposes sensitive data (a secret) in the response, which could be leaked to users or attackers.',
        'resources' => [
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
            'https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage.html'
        ]
    ]
];
