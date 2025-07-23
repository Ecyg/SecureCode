# SecureCode

A web application for reviewing and learning about vulnerable code snippets, inspired by the OWASP Top 10 and other common security issues. Snippets are provided in multiple programming languages, and each snippet includes a description of the vulnerability and resources to learn more.

## Features
- Browse code snippets vulnerable to OWASP Top 10 and other security issues
- Multi-language support (PHP, Python, JavaScript, Java, Go, C, C#, Ruby, Perl, etc.)
- Sidebar organized by language, with collapsible sections
- See vulnerability details and learning resources for each snippet
- Add your own snippets easily

## Getting Started

### Run Locally (PHP Built-in Server)
1. Clone the repository:
   ```sh
   git clone https://github.com/Ecyg/SecureCode.git
   cd your-repo
   ```
2. Start the PHP server:
   ```sh
   php -S localhost:8000
   ```
3. Open [http://localhost:8000](http://localhost:8000) in your browser.

### Run with Docker (Local Files)
1. Build the Docker image:
   ```sh
   docker build -t securecode-app .
   ```
2. Run the container:
   ```sh
   docker run -p 8080:80 securecode-app
   ```
3. Open [http://localhost:8080](http://localhost:8080) in your browser.

### Run with Docker (GitHub Clone)
1. Edit the `Dockerfile` and set your repository URL in the `git clone` line.
2. Build and run as above.

## Adding New Snippets
- Edit `snippets.php`.
- Add a new array entry with:
  - `id` (unique integer)
  - `title` (include language in parentheses, e.g., `SQL Injection (PHP)`)
  - `code` (multi-line string, use single quotes and escape as needed)
  - `vulnerability` (name)
  - `summary` (short description)
  - `resources` (array of URLs)


## Credits
- Inspired by [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- Created for educational and demonstration purposes

---
**Never use these code patterns in production!** 