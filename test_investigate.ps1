$token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc3MjIyMDc4M30.VwmeL3wXQtxGAcFcEkx4kwh_khxKDsKLKWdsv3JWZZs"

$result = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/dashboard/investigate/paypal-verify.ml" -Method GET -Headers @{Authorization="Bearer $token"}
$result | ConvertTo-Json -Depth 10
