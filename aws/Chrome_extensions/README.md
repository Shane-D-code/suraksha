# PhishGuard Chrome Extension

## Overview
AI-powered multi-channel phishing detection for web, email, and messaging platforms.

## Features
- **Real-time Page Scanning**: Automatically scans websites for phishing threats
- **Email Protection**: Scans Gmail messages for phishing attempts
- **Messaging Protection**: Works with WhatsApp Web, Telegram Web, Discord, Slack
- **Hybrid AI**: Combines local rule-based detection with backend ML models
- **Visual Indicators**: Shows risk levels with color-coded badges
- **Blocking System**: Blocks high-risk pages with full-screen overlay
- **Dashboard Integration**: Connects to SOC dashboard for enterprise monitoring

## Installation

### Method 1: Developer Mode (Recommended for Development)

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right corner)
3. Click "Load unpacked"
4. Select the `aws/Chrome_extensions/` folder
5. The extension icon will appear in your toolbar

### Method 2: Build and Install

```bash
cd aws/Chrome_extensions/dashboard
npm install
npm run build
```

Then load the extension from the `aws/Chrome_extensions/` folder.

## Configuration

### Backend API Connection
The extension connects to the PhishGuard backend API at `http://localhost:8000`.

To change the API endpoint, edit `background.js`:
```javascript
const API_ENDPOINT = 'http://localhost:8000/api/v1/scan';
```

### Dashboard Access
The SOC dashboard runs at `http://localhost:5173`
- Username: `admin`
- Password: `admin123`

## How It Works

### 1. Page Scanning
When you visit a website:
1. Content script extracts page features (URL, forms, text content)
2. Local AI runs quick rule-based analysis
3. If medium/high risk, sends to backend for ML analysis
4. Displays warning banner or blocks page if high risk

### 2. Email Scanning (Gmail)
When viewing emails in Gmail:
1. Scanner detects email content
2. Analyzes sender, subject, body, and links
3. Shows risk indicator in email interface

### 3. Message Scanning
For messaging platforms:
1. Monitors message content in real-time
2. Scans links and suspicious text patterns
3. Alerts on potential phishing attempts

## Risk Levels

- **LOW** (Green): Safe to proceed
- **MEDIUM** (Orange): Warning banner shown, proceed with caution
- **HIGH** (Red): Page blocked with full-screen overlay

## User Override

If a page is blocked, users can:
1. Click "Go Back to Safety" to return to previous page
2. Click "Proceed Anyway" to override (sends feedback to backend)

## Files Structure

```
aws/Chrome_extensions/
├── manifest.json          # Extension configuration
├── background.js          # Service worker (API communication)
├── content.js            # Page scanning logic
├── local_inference.js    # On-device AI detection
├── blocker.js            # Visual blocking system
├── popup.html            # Extension popup UI
├── popup.js              # Popup logic
├── styles.css            # Popup styles
├── overlay.css           # Blocking overlay styles
├── gmail_scanner.js      # Gmail integration
├── message_scanner.js    # Messaging platform integration
├── icons/                # Extension icons
└── dashboard/            # React SOC Dashboard
    ├── src/
    │   ├── App.jsx       # Main dashboard app
    │   ├── main.jsx      # Entry point
    │   └── dashboard.css   # Dashboard styles
    ├── index.html
    ├── package.json
    └── vite.config.js
```

## API Endpoints Used

- `POST /api/v1/scan` - Scan URLs/content
- `POST /api/v1/feedback` - Submit user feedback
- `GET /api/v1/dashboard/summary` - Dashboard overview
- `GET /api/v1/dashboard/live-threats` - Live threat feed
- `GET /api/v1/dashboard/campaigns` - Campaign data
- `GET /api/v1/dashboard/graph` - Infrastructure graph
- `POST /api/v1/auth/login` - Dashboard authentication

## Troubleshooting

### Extension Not Working
1. Check backend is running: `curl http://localhost:8000/health`
2. Check dashboard is running: `curl http://localhost:5173`
3. Open Chrome DevTools (F12) → Console for error messages
4. Check extension background page: chrome://extensions/ → Details → Service Worker

### Backend Connection Failed
- Ensure backend is running on port 8000
- Check CORS settings in `app/main.py`
- Verify firewall isn't blocking localhost

### Dashboard Not Loading
- Ensure Vite dev server is running on port 5173
- Check `vite.config.js` proxy settings
- Clear browser cache

## Development

### Local Development
```bash
# Start all services
python start_all_services.py

# Or start individually:
# Backend
uvicorn app.main:app --reload --port 8000

# Dashboard
cd aws/Chrome_extensions/dashboard
npm run dev
```

### Building for Production
```bash
cd aws/Chrome_extensions/dashboard
npm run build
```

The built files will be in `aws/Chrome_extensions/dashboard/dist/`.

## Security Notes

- Extension uses `host_permissions: ["<all_urls>"]` to scan any website
- All data is processed locally first, then sent to backend if needed
- User override actions are logged for model improvement
- JWT tokens are used for dashboard authentication

## License
Enterprise - PhishGuard Threat Intelligence Platform
