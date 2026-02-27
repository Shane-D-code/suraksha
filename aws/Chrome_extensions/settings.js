// PhishGuard Settings Manager

// Default settings
const DEFAULT_SETTINGS = {
  enableLocalAI: true,
  privacyMode: true,
  performanceLogging: true
};

// Load settings on page load
document.addEventListener('DOMContentLoaded', async () => {
  const settings = await loadSettings();
  
  // Update UI
  document.getElementById('enable-local-ai').checked = settings.enableLocalAI;
  document.getElementById('privacy-mode').checked = settings.privacyMode;
  document.getElementById('performance-logging').checked = settings.performanceLogging;
  
  updateStatusBadge(settings.enableLocalAI);
});

// Load settings from storage
async function loadSettings() {
  try {
    const result = await chrome.storage.local.get('phishguard_settings');
    return result.phishguard_settings || DEFAULT_SETTINGS;
  } catch (error) {
    console.error('Failed to load settings:', error);
    return DEFAULT_SETTINGS;
  }
}

// Save settings to storage
async function saveSettings(settings) {
  try {
    await chrome.storage.local.set({ phishguard_settings: settings });
    return true;
  } catch (error) {
    console.error('Failed to save settings:', error);
    return false;
  }
}

// Update status badge
function updateStatusBadge(enabled) {
  const badge = document.getElementById('ai-status');
  if (enabled) {
    badge.textContent = 'Enabled';
    badge.className = 'status enabled';
  } else {
    badge.textContent = 'Disabled';
    badge.className = 'status disabled';
  }
}

// Save button handler
document.getElementById('save-button').addEventListener('click', async () => {
  const settings = {
    enableLocalAI: document.getElementById('enable-local-ai').checked,
    privacyMode: document.getElementById('privacy-mode').checked,
    performanceLogging: document.getElementById('performance-logging').checked
  };
  
  const saveButton = document.getElementById('save-button');
  const successMessage = document.getElementById('success-message');
  
  // Disable button during save
  saveButton.disabled = true;
  saveButton.textContent = 'Saving...';
  
  const success = await saveSettings(settings);
  
  if (success) {
    // Show success message
    successMessage.classList.add('show');
    setTimeout(() => {
      successMessage.classList.remove('show');
    }, 3000);
    
    updateStatusBadge(settings.enableLocalAI);
  }
  
  // Re-enable button
  saveButton.disabled = false;
  saveButton.textContent = 'Save Settings';
});

// Toggle change handlers
document.getElementById('enable-local-ai').addEventListener('change', (e) => {
  updateStatusBadge(e.target.checked);
});
