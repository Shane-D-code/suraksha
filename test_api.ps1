$body = @{
    url = "https://example.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri 'http://localhost:8000/api/v1/scan' -Method Post -Body $body -ContentType 'application/json'
