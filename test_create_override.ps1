$token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc3MjIyMDc4M30.VwmeL3wXQtxGAcFcEkx4kwh_khxKDsKLKWdsv3JWZZs"

$body = @{
    domain = "test-new-domain.com"
    action = "BLOCK"
    reason = "Testing new override creation"
} | ConvertTo-Json

$result = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/admin/overrides" -Method POST -ContentType "application/json" -Headers @{Authorization="Bearer $token"} -Body $body
$result | ConvertTo-Json -Depth 10
