#!/usr/bin/env python3
"""Script to fix routes.py - remove mock data from risk-trends endpoint"""

import re

# Read the file
with open('app/api/routes.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the mock data block in get_risk_trends
old_pattern = r'''@router\.get\("/dashboard/risk-trends"\)
async def get_risk_trends\(
    days: int = Query\(default=7, ge=1, le=30\)
\):
    """Get risk trend data - returns mock demo data"""
    from datetime import datetime, timedelta
    
    # Return comprehensive mock data for demo visualization
    trends = \[\]
    for i in range\(days\):
        date = datetime\.utcnow\(\) - timedelta\(days=days - 1 - i\)
        trends\.append\(\{
            "date": date\.strftime\("%Y-%m-%d"\),
            "blocked_count": 42 \+ \(i \* 7\) \+ \(i % 3\) \* 5,
            "zero_day_count": 8 \+ \(i \* 2\) \+ \(i % 2\) \* 3,
            "new_campaigns": 5 \+ \(i \* 1\) \+ \(i % 4\),
            "avg_risk_score": round\(0\.42 \+ \(i \* 0\.08\) \+ \(i % 5\) \* 0\.03, 2\)
        \}\)
    return trends
    
    try:'''

new_text = '''@router.get("/dashboard/risk-trends")
async def get_risk_trends(
    days: int = Query(default=7, ge=1, le=30)
):
    """Get risk trend data - queries real database data"""
    from datetime import datetime, timedelta
    
    try:'''

content = re.sub(old_pattern, new_text, content)

# Write back
with open('app/api/routes.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed routes.py - removed mock data block from get_risk_trends")
