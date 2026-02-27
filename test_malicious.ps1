# Test with a known phishing URL pattern
$body = @{
    url = "https://paypal-verify-secure.ml/login"
} | ConvertTo-Json

Write-Host "Testing malicious URL detection..."
$result = Invoke-RestMethod -Uri 'http://localhost:8000/api/v1/scan' -Method Post -Body $body -ContentType 'application/json'
$result | ConvertTo-Json -Depth 5
