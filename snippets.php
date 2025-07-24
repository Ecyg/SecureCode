<?php
// snippets.php

return [
    [
        'id' => 1,
        'title' => 'SQL Injection (PHP)',
        'code' => "<?php
include \"db.php\";
\$username = \$_GET[\"username\"];
\$password = \$_GET[\"password\"];
\$query = \"SELECT * FROM users WHERE username = '\$username' AND password = '\$password'\";
\$result = mysqli_query(\$conn, \$query);
if (\$row = mysqli_fetch_assoc(\$result)) {
    echo \"Welcome, \" . \$row[\"username\"];
} else {
    echo \"Invalid login.\";
}
?>",
        'vulnerability' => 'SQL Injection',
        'summary' => 'User input is directly embedded into the SQL query without sanitization or parameterization. An attacker could submit a username like admin\' -- to bypass authentication or inject malicious SQL. To fix this, use prepared statements with parameterized queries (e.g., mysqli_prepare and mysqli_stmt_bind_param in PHP) to separate SQL logic from user input.',
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
        'summary' => 'User input is output directly to the page without escaping. An attacker could submit a message like <script>alert(1)</script> which would execute in the browser of anyone viewing the messages. To fix this, always escape output using htmlspecialchars($string, ENT_QUOTES) before rendering user data in HTML.',
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
        'summary' => 'The code allows users to access arbitrary files by manipulating the file parameter. An attacker could request ?file=../../etc/passwd to read sensitive files. To fix this, validate the file name against a whitelist of allowed files or ensure the user is authorized to access the requested file.',
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
        'summary' => 'User input is written directly into the DOM using innerHTML without sanitization. An attacker could enter <img src=x onerror=alert(1)> as a comment, which would execute JavaScript in the browser. To fix this, use a library like DOMPurify to sanitize user input before inserting it into the DOM, or use textContent instead of innerHTML.',
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
        'summary' => 'User input is concatenated into a shell command without validation or sanitization. An attacker could supply filename=foo;rm -rf / to execute arbitrary commands. To fix this, use Python\'s subprocess.run with a list of arguments and never pass user input to the shell, or strictly validate the filename.',
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
        'summary' => 'The code deserializes untrusted data from the request. An attacker could send a malicious object to achieve remote code execution. To fix this, avoid Java serialization for untrusted data, use safe data formats like JSON, or use an allowlist of classes for deserialization.',
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
        'summary' => 'The file name from user input is not sanitized or validated. An attacker could request files like ../../etc/passwd to read sensitive files. To fix this, validate the file name against a whitelist, use path normalization, and never allow .. or absolute paths in user input.',
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
        'summary' => 'Sensitive data (a secret) is included in the response and log file. An attacker could access the secret if they can view the debug output or logs. To fix this, never include secrets in error messages or logs accessible to users, and use environment variables or secure vaults for secrets.',
        'resources' => [
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
            'https://cheatsheetseries.owasp.org/cheatsheets/Information_Leakage.html'
        ]
    ],
    [
        'id' => 9,
        'title' => 'Server-Side Request Forgery (SSRF) (Ruby)',
        'code' => 'require "net/http"
require "uri"

url = params[:url]
uri = URI.parse(url)
response = Net::HTTP.get_response(uri)
render plain: response.body',
        'vulnerability' => 'Server-Side Request Forgery (SSRF)',
        'summary' => 'The code fetches a URL provided by the user without validation. An attacker could supply a URL like http://localhost:8080/admin to access internal resources. To fix this, validate and restrict the allowed URLs, block internal IP ranges, and use allowlists for external domains.',
        'resources' => [
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 10,
        'title' => 'XML External Entity (XXE) (Java)',
        'code' => 'import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import org.xml.sax.InputSource;

String xml = request.getParameter("xml");
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xml)));
',
        'vulnerability' => 'XML External Entity (XXE)',
        'summary' => 'The XML parser does not disable external entity resolution. An attacker could supply XML that reads local files or makes network requests. To fix this, disable external entity resolution on the XML parser using dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and related features.',
        'resources' => [
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 11,
        'title' => 'Hardcoded Credentials (C#)',
        'code' => 'using System;
class Program {
    static void Main() {
        string user = "admin";
        string pass = "password123";
        Console.WriteLine("Connecting with user: " + user);
        // ... connect to database ...
    }
}',
        'vulnerability' => 'Hardcoded Credentials',
        'summary' => 'Credentials are hardcoded in the source code. An attacker could extract these credentials from the code or binary and use them to access sensitive systems. To fix this, store credentials in environment variables or secure vaults, and never commit secrets to source control.',
        'resources' => [
            'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
            'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 12,
        'title' => 'Open Redirect (Go)',
        'code' => 'package main
import (
    "net/http"
)
func handler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("next")
    http.Redirect(w, r, url, http.StatusFound)
}
func main() {
    http.HandleFunc("/redirect", handler)
    http.ListenAndServe(":8080", nil)
}',
        'vulnerability' => 'Open Redirect',
        'summary' => 'The code redirects to a URL provided by the user without validation. An attacker could use this to redirect users to a malicious site. To fix this, validate the next parameter against a whitelist of allowed URLs or only allow relative paths.',
        'resources' => [
            'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards',
            'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 13,
        'title' => 'Unrestricted File Upload (PHP)',
        'code' => '<?php
if (isset($_FILES["file"])) {
    $uploadDir = "/var/www/uploads/";
    $uploadFile = $uploadDir . basename($_FILES["file"]["name"]);
    move_uploaded_file($_FILES["file"]["tmp_name"], $uploadFile);
    echo "File uploaded!";
}
?>',
        'vulnerability' => 'Unrestricted File Upload',
        'summary' => 'Any file can be uploaded without checking the file type or content. An attacker could upload a PHP file and execute code on the server. To fix this, validate the file type and extension, use random file names, and store uploads outside the web root.',
        'resources' => [
            'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
        ]
    ],
    [
        'id' => 14,
        'title' => 'Format String Vulnerability (C)',
        'code' => '#include <stdio.h>
int main(int argc, char *argv[]) {
    char buf[100];
    strcpy(buf, argv[1]);
    printf(buf);
    return 0;
}',
        'vulnerability' => 'Format String Vulnerability',
        'summary' => 'User input is passed directly as the format string to printf. An attacker could supply %x%x%x to read memory or execute code. To fix this, always use a static format string, e.g., printf("%s", buf).',
        'resources' => [
            'https://owasp.org/www-community/attacks/Format_string_attack',
            'https://cwe.mitre.org/data/definitions/134.html'
        ]
    ],
    [
        'id' => 15,
        'title' => 'Insecure Temporary File (Perl)',
        'code' => 'my $tmpfile = "/tmp/myapp.tmp";
open(my $fh, ">", $tmpfile) or die $!;
print $fh "Sensitive data\n";
close($fh);
# ... later ...
unlink $tmpfile;',
        'vulnerability' => 'Insecure Temporary File',
        'summary' => 'A predictable temporary file is created in /tmp. An attacker could create a symlink or file at that path to overwrite or read sensitive data. To fix this, use secure temporary file creation functions like File::Temp that create files with random names and proper permissions.',
        'resources' => [
            'https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File',
            'https://cwe.mitre.org/data/definitions/377.html'
        ]
    ]
];
