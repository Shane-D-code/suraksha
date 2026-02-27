# Script to remove auth requirement from dashboard endpoints

with open('app/api/routes.py', 'r') as f:
    content = f.read()

# Remove auth from get_endpoint_stats
content = content.replace(
    '''@router.get("/dashboard/endpoint-stats")
async def get_endpoint_stats(current_user: dict = Depends(get_current_user)):''',
    '''@router.get("/dashboard/endpoint-stats")
async def get_endpoint_stats():'''
)

# Remove auth from get_risk_trends  
content = content.replace(
    '''@router.get("/dashboard/risk-trends")
async def get_risk_trends(
    days: int = Query(default=7, ge=1, le=30),
    current_user: dict = Depends(get_current_user)
):''',
    '''@router.get("/dashboard/risk-trends")
async def get_risk_trends(
    days: int = Query(default=7, ge=1, le=30)
):'''
)

with open('app/api/routes.py', 'w') as f:
    f.write(content)

print("Auth removed from dashboard endpoints!")
