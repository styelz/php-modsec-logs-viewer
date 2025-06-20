# PHP ModSecurity Logs Viewer

## Overview
The PHP ModSecurity Logs Viewer is a lightweight web application for viewing and analyzing ModSecurity logs in a user-friendly, searchable, and color-coded interface.

## Project Structure
```
modsec-web/
├── index.php      # Main PHP application file
└── style.css      # CSS styles for the web application
```

## Setup Instructions
1. Clone the repository:
   ```
   git clone https://github.com/styelz/php-modsec-logs-viewer.git
   ```
2. Navigate to the project directory:
   ```
   cd php-modsec-logs-viewer
   ```
3. Ensure you have a web server with PHP support (e.g., Apache, Nginx) set up.
4. Place the project files in the web server's document root.

## Usage Guidelines
1. Open your web browser and navigate to `http://localhost/php-modsec-logs-viewer/index.php`.
2. The application will display the parsed ModSecurity logs.
3. Use the search box in the "Target" column header to filter by hostname.
4. Click any row to view the full raw log entry in a modal.

## Features

- **Dark theme** for comfortable viewing.
- **Sortable columns**: Click any column header to sort.
- **Live search**: Filter logs by hostname directly in the table header.
- **Severity highlighting**: Severity levels are color-coded for quick scanning.
- **Pastel rule ID colors**: Each unique rule ID is shown in a different pastel color.
- **Raw log modal**: Click a row to view the full raw log in a modal window.
- **Responsive design** for desktop and mobile browsers.

## ModSecurity Logs
ModSecurity logs contain information about security events detected by the ModSecurity web application firewall. The logs typically include details such as:
- Timestamp of the event
- IP address of the client
- Request method and URL
- Response status code
- Anomaly score and rule ID

Understanding these logs is crucial for identifying potential security threats and taking appropriate actions.

## Contributing
Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file