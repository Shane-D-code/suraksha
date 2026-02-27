/**
 * PhishGuard Enterprise SOC Dashboard
 * Tactical Operations Center - Complete Redesign
 */

import React, { useState, useEffect, useCallback } from 'react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './dashboard.css';

// API Base URL
const API_BASE = '/api/v1';

// Colors
const COLORS = ['#FF3333', '#FFFF00', '#00FF66', '#00FFFF', '#39FF14', '#8B5CF6'];

// ============== LOGIN ==============

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData
      });

      if (!response.ok) throw new Error('Invalid credentials');

      const data = await response.json();
      onLogin(data.access_token, data.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="vignette"></div>
      <div className="login-box">
        <h1 className="neon-glow-intense">PHISHGUARD</h1>
        <p className="subtitle">TACTICAL OPERATIONS CENTER</p>
        
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="USERNAME"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="input"
          />
          <input
            type="password"
            placeholder="PASSWORD"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="input"
          />
          {error && <div className="alert alert-error">{error}</div>}
          <button type="submit" disabled={loading} className="btn btn-primary">
            {loading ? 'AUTHENTICATING...' : 'INITIATE'}
          </button>
        </form>
        
        <div className="demo-credentials">
          <p>demo: admin / admin123</p>
        </div>
      </div>
    </div>
  );
}

// ============== SIDEBAR ==============

function Sidebar({ activeView, setActiveView }) {
  const menuItems = [
    { id: 'overview', icon: '◉', label: 'Overview' },
    { id: 'live-threats', icon: '◈', label: 'Live Threats' },
    { id: 'campaigns', icon: '◎', label: 'Campaigns' },
    { id: 'graph', icon: '◇', label: 'Infrastructure' },
    { id: 'endpoints', icon: '□', label: 'Endpoints' },
    { id: 'trends', icon: '△', label: 'Trends' },
    { id: 'investigate', icon: '▽', label: 'Investigate' },
    { id: 'admin', icon: '⚙', label: 'Admin' },
  ];

  return (
    <aside className="sidebar">
      <nav className="sidebar-nav">
        {menuItems.map(item => (
          <button
            key={item.id}
            className={`nav-item ${activeView === item.id ? 'active' : ''}`}
            onClick={() => setActiveView(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span className="nav-label">{item.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}

// ============== HEADER ==============

function Header({ user, onLogout }) {
  return (
    <header className="app-header">
      <div className="header-left">
        <div className="logo">
          <h1 className="neon-glow">PHISHGUARD</h1>
          <span className="logo-badge">TACTICAL OPS</span>
        </div>
      </div>
      
      <div className="header-center">
        <input
          type="text"
          className="header-search"
          placeholder="Search domains, IPs, or campaigns..."
        />
      </div>
      
      <div className="header-right">
        <button className="header-btn notification-btn">
          <span>🔔</span>
          <span className="notification-badge">3</span>
        </button>
        
        <div className="user-menu">
          <div className="user-avatar">SA</div>
          <div className="user-info">
            <span className="user-name">Security Admin</span>
            <span className="user-role">Administrator</span>
          </div>
        </div>
        
        <button className="header-btn" onClick={onLogout}>
          ⏻ LOGOUT
        </button>
      </div>
    </header>
  );
}

// ============== OVERVIEW ==============

function OverviewDashboard({ token }) {
  const [summary, setSummary] = useState(null);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Fetch both summary and real-time stats
    Promise.all([
      fetch(`${API_BASE}/dashboard/summary`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).then(res => res.json()),
      fetch(`${API_BASE}/dashboard/stats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).then(res => res.json())
    ])
      .then(([summaryData, statsData]) => {
        setSummary(summaryData);
        setStats(statsData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [token]);

  // Set up real-time updates
  useEffect(() => {
    if (!stats) return;
    
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/dashboard/stats`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        setStats(data);
      } catch (err) {
        console.error('Stats refresh error:', err);
      }
    }, 5000); // Update every 5 seconds
    
    return () => clearInterval(interval);
  }, [token, stats]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      {/* Stats Row - Using real-time data */}
      <div className="stats-grid">
        <div className="stat-card">
          <h3>◈ SCANS TODAY</h3>
          <div className="stat-value">{stats?.total_scans_today || 0}</div>
          <div className="stat-trend positive">▲ Live</div>
        </div>
        
        <div className="stat-card">
          <h3>◉ THREATS BLOCKED</h3>
          <div className="stat-value text-danger">{stats?.threats_detected_today || 0}</div>
          <div className="stat-trend negative">Live detection</div>
        </div>
        
        <div className="stat-card">
          <h3>◎ AVG RISK SCORE</h3>
          <div className="stat-value text-warning">{((stats?.avg_risk_score || 0) * 100).toFixed(1)}%</div>
          <div className="stat-trend">Real-time</div>
        </div>
        
        <div className="stat-card">
          <h3>◇ SCANS/MIN</h3>
          <div className="stat-value text-success">{stats?.scans_per_minute?.toFixed(1) || 0}</div>
          <div className="stat-trend positive">▲ Live rate</div>
        </div>
      </div>

      {/* Content Grid */}
      <div className="content-grid">
        {/* Threat Trend Chart */}
        <div className="content-card">
          <h3>THREAT TREND - LAST 7 DAYS</h3>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={[
              {date: 'Mon', blocked: 280},
              {date: 'Tue', blocked: 320},
              {date: 'Wed', blocked: 290},
              {date: 'Thu', blocked: 350},
              {date: 'Fri', blocked: 310},
              {date: 'Sat', blocked: 180},
              {date: 'Sun', blocked: 150}
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0D3D0D" />
              <XAxis dataKey="date" tick={{fill: '#1A5C0A', fontSize: 12}} />
              <YAxis tick={{fill: '#1A5C0A', fontSize: 12}} />
              <Tooltip contentStyle={{background: '#020617', border: '1px solid #39FF14', color: '#39FF14'}} />
              <Line type="monotone" dataKey="blocked" stroke="#FF3333" strokeWidth={2} dot={{fill: '#FF3333'}} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Top Brands */}
        <div className="content-card">
          <h3>TOP TARGETED BRANDS</h3>
          <div className="brand-list">
            {summary?.top_targeted_brands?.map((brand, i) => (
              <div key={i} className="brand-item">
                <span className="brand-name">{brand.brand}</span>
                <div className="brand-bar">
                  <div className="brand-fill" style={{width: `${(brand.attempts / summary.top_targeted_brands[0].attempts) * 100}%`}} />
                </div>
                <span className="brand-count">{brand.attempts}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Activity Feed */}
      <div className="content-card">
        <h3>RECENT ACTIVITY</h3>
        <div className="activity-feed">
          {summary?.recent_activity?.map((activity, i) => (
            <div key={i} className="activity-item">
              <span className="activity-time">{activity.time}</span>
              <span className="activity-event">{activity.event}</span>
              <span className={`campaign-badge ${activity.severity}`}>{activity.severity}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ============== LIVE THREATS ==============

function LiveThreats({ token }) {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchThreats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/live-threats?limit=20`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setThreats(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchThreats();
    const interval = setInterval(fetchThreats, 5000);
    return () => clearInterval(interval);
  }, [fetchThreats]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      <div className="content-card">
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px'}}>
          <h3 style={{marginBottom: 0, borderBottom: 'none', paddingBottom: 0}}>LIVE THREAT FEED</h3>
          <div className="status-badge">
            <span className="status-dot"></span>
            LIVE
          </div>
        </div>
        
        <table className="threats-table">
          <thead>
            <tr>
              <th>DOMAIN</th>
              <th>RISK SCORE</th>
              <th>CONFIDENCE</th>
              <th>SOURCE</th>
              <th>CAMPAIGN</th>
              <th>TIMESTAMP</th>
            </tr>
          </thead>
          <tbody>
            {threats.map(threat => (
              <tr key={threat.id} className="threat-row">
                <td>{threat.domain}</td>
                <td>
                  <div style={{display: 'flex', alignItems: 'center', gap: '10px'}}>
                    <div style={{width: '80px', height: '8px', background: '#0D3D0D'}}>
                      <div style={{width: `${threat.risk_score * 100}%`, height: '100%', background: threat.risk_score > 0.7 ? '#FF3333' : threat.risk_score > 0.4 ? '#FFFF00' : '#00FF66'}} />
                    </div>
                    <span>{(threat.risk_score * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td>{(threat.confidence * 100).toFixed(0)}%</td>
                <td>
                  <span style={{
                    padding: '4px 10px',
                    background: threat.detection_source === 'GNN' ? '#8B5CF6' : threat.detection_source === 'NLP' ? '#00FFFF' : '#F97316',
                    color: '#020617',
                    fontWeight: 'bold',
                    fontSize: '11px'
                  }}>
                    {threat.detection_source}
                  </span>
                </td>
                <td>{threat.campaign_id || '—'}</td>
                <td>{new Date(threat.timestamp).toLocaleTimeString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ============== CAMPAIGNS ==============

function CampaignsView({ token }) {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/dashboard/campaigns`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => setCampaigns(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      <div className="campaigns-grid">
        {campaigns.map(campaign => (
          <div key={campaign.campaign_id} className="campaign-card">
            <div className="campaign-header">
              <span className="campaign-title">{campaign.campaign_id}</span>
              <span className="campaign-badge" style={{
                background: campaign.growth_trend === 'growing' ? 'rgba(255,51,51,0.2)' : 'rgba(0,255,102,0.2)',
                border: `1px solid ${campaign.growth_trend === 'growing' ? '#FF3333' : '#00FF66'}`,
                color: campaign.growth_trend === 'growing' ? '#FF3333' : '#00FF66'
              }}>
                {campaign.growth_trend === 'growing' ? '▲ GROWING' : '▶ STABLE'}
              </span>
            </div>
            
            <div className="campaign-stats">
              <div>
                <div className="campaign-stat-label">Cluster Size</div>
                <div className="campaign-stat-value">{campaign.cluster_size} domains</div>
              </div>
              <div>
                <div className="campaign-stat-label">Avg Risk</div>
                <div className="campaign-stat-value">{(campaign.avg_risk_score * 100).toFixed(0)}%</div>
              </div>
              <div>
                <div className="campaign-stat-label">First Seen</div>
                <div className="campaign-stat-value">{new Date(campaign.first_seen).toLocaleDateString()}</div>
              </div>
            </div>
            
            <div style={{marginTop: '16px', padding: '12px', background: '#0A1525', border: '1px solid #0D3D0D'}}>
              <div style={{fontSize: '12px', color: '#1A5C0A', marginBottom: '8px', fontFamily: 'var(--font-display)'}}>SHARED INFRASTRUCTURE</div>
              <div style={{display: 'flex', gap: '24px', fontSize: '13px'}}>
                <span><span style={{color: '#1A5C0A'}}>IP:</span> {campaign.shared_ip}</span>
                <span><span style={{color: '#1A5C0A'}}>CERT:</span> {campaign.shared_cert}</span>
              </div>
            </div>
            
            <div style={{marginTop: '16px'}}>
              <div style={{fontSize: '12px', color: '#1A5C0A', marginBottom: '8px', fontFamily: 'var(--font-display)'}}>DOMAINS ({campaign.domains.length})</div>
              <div style={{fontSize: '13px', color: '#00FF9C', fontFamily: 'var(--font-mono)'}}>
                {campaign.domains.slice(0, 3).join(', ')}
                {campaign.domains.length > 3 && <span style={{color: '#1A5C0A'}}> +{campaign.domains.length - 3} more</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============== GRAPH ==============

function InfrastructureGraph({ token }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchGraph = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/dashboard/graph`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setGraphData(data);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Graph fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchGraph();
    // Refresh graph every 10 seconds to show newly scanned domains
    const interval = setInterval(fetchGraph, 10000);
    return () => clearInterval(interval);
  }, [fetchGraph]);

  if (loading) return <div className="loading"></div>;

  const nodes = graphData?.nodes?.map((node, i) => ({
    ...node,
    x: 100 + (i % 4) * 200,
    y: 100 + Math.floor(i / 4) * 150
  })) || [];

  return (
    <div className="page-content">
      <div className="content-card">
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px'}}>
          <h3 style={{marginBottom: 0, borderBottom: 'none', paddingBottom: 0}}>THREAT INFRASTRUCTURE GRAPH</h3>
          <div style={{display: 'flex', alignItems: 'center', gap: '16px'}}>
            {lastUpdated && (
              <span style={{fontSize: '12px', color: '#1A5C0A', fontFamily: 'var(--font-mono)'}}>
                Updated: {lastUpdated.toLocaleTimeString()}
              </span>
            )}
            <button 
              onClick={fetchGraph}
              style={{
                background: 'transparent',
                border: '1px solid #39FF14',
                color: '#39FF14',
                padding: '6px 12px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '12px',
                fontFamily: 'var(--font-mono)'
              }}
            >
              ↻ REFRESH
            </button>
          </div>
        </div>
        <div className="graph-container">
          <svg viewBox="0 0 800 500" style={{width: '100%', height: '500px'}}>
            {graphData?.edges?.map((edge, i) => {
              const source = nodes.find(n => n.id === edge.source);
              const target = nodes.find(n => n.id === edge.target);
              if (!source || !target) return null;
              return (
                <line
                  key={i}
                  x1={source.x} y1={source.y}
                  x2={target.x} y2={target.y}
                  stroke="#39FF14"
                  strokeWidth="1"
                  strokeOpacity="0.3"
                />
              );
            })}
            
            {nodes.map(node => (
              <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
                <circle
                  r={node.type === 'domain' ? 25 : 20}
                  fill={node.risk > 0.7 ? '#FF3333' : node.risk > 0.4 ? '#FFFF00' : '#00FF66'}
                  stroke="#39FF14"
                  strokeWidth="1"
                  opacity="0.8"
                />
                <text y={40} textAnchor="middle" fill="#39FF14" fontSize="9" fontFamily="var(--font-mono)">
                  {node.label.length > 15 ? node.label.slice(0, 15) + '...' : node.label}
                </text>
              </g>
            ))}
          </svg>
        </div>
      </div>
    </div>
  );
}

// ============== ENDPOINTS ==============

function EndpointsView({ token }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/dashboard/endpoint-stats`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => setStats(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      <div className="endpoint-grid">
        <div className="endpoint-stat">
          <div className="endpoint-stat-icon neon-glow">◈</div>
          <div className="endpoint-stat-value">{stats?.total_endpoints?.toLocaleString()}</div>
          <div className="endpoint-stat-label">Total Endpoints</div>
        </div>
        
        <div className="endpoint-stat">
          <div className="endpoint-stat-icon neon-glow">◉</div>
          <div className="endpoint-stat-value">{stats?.scans_per_minute}</div>
          <div className="endpoint-stat-label">Scans/Minute</div>
        </div>
        
        <div className="endpoint-stat">
          <div className="endpoint-stat-icon" style={{color: '#FF3333'}}>◼</div>
          <div className="endpoint-stat-value text-danger">{stats?.blocked_attempts?.toLocaleString()}</div>
          <div className="endpoint-stat-label">Blocked Attempts</div>
        </div>
        
        <div className="endpoint-stat">
          <div className="endpoint-stat-icon" style={{color: '#FFFF00'}}>◻</div>
          <div className="endpoint-stat-value text-warning">{(stats?.override_rate * 100).toFixed(1)}%</div>
          <div className="endpoint-stat-label">Override Rate</div>
        </div>
      </div>

      <div className="content-card" style={{marginTop: '28px'}}>
        <h3>SCANS OVER TIME</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={[
            {time: '00:00', scans: 45},
            {time: '04:00', scans: 32},
            {time: '08:00', scans: 78},
            {time: '12:00', scans: 95},
            {time: '16:00', scans: 88},
            {time: '20:00', scans: 65},
            {time: '24:00', scans: 48}
          ]}>
            <CartesianGrid strokeDasharray="3 3" stroke="#0D3D0D" />
            <XAxis dataKey="time" tick={{fill: '#1A5C0A', fontSize: 12}} />
            <YAxis tick={{fill: '#1A5C0A', fontSize: 12}} />
            <Tooltip contentStyle={{background: '#020617', border: '1px solid #39FF14', color: '#39FF14'}} />
            <Area type="monotone" dataKey="scans" stroke="#00FF66" fill="rgba(0,255,102,0.2)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Import AreaChart
import { AreaChart, Area } from 'recharts';

// ============== TRENDS ==============

function TrendsView({ token }) {
  const [trends, setTrends] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API_BASE}/dashboard/risk-trends?days=7`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => setTrends(data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      <div className="charts-grid">
        <div className="chart-card">
          <h3>DAILY BLOCKED THREATS</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0D3D0D" />
              <XAxis dataKey="date" tick={{fill: '#1A5C0A', fontSize: 11}} />
              <YAxis tick={{fill: '#1A5C0A', fontSize: 11}} />
              <Tooltip contentStyle={{background: '#020617', border: '1px solid #39FF14', color: '#39FF14'}} />
              <Line type="monotone" dataKey="blocked_count" stroke="#FF3333" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        
        <div className="chart-card">
          <h3>ZERO-DAY DETECTIONS</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0D3D0D" />
              <XAxis dataKey="date" tick={{fill: '#1A5C0A', fontSize: 11}} />
              <YAxis tick={{fill: '#1A5C0A', fontSize: 11}} />
              <Tooltip contentStyle={{background: '#020617', border: '1px solid #39FF14', color: '#39FF14'}} />
              <Bar dataKey="zero_day_count" fill="#FFFF00" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        
        <div className="chart-card">
          <h3>CAMPAIGN DISTRIBUTION</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={trends}
                dataKey="new_campaigns"
                nameKey="date"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label={({date, new_campaigns}) => `${date}: ${new_campaigns}`}
                labelLine={{stroke: '#1A5C0A'}}
              >
                {trends.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{background: '#020617', border: '1px solid #39FF14', color: '#39FF14'}} />
              <Legend 
                formatter={(value, entry) => <span style={{color: '#39FF14', fontSize: '12px'}}>{value}</span>}
                wrapperStyle={{paddingTop: '10px'}}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{marginTop: '10px', display: 'flex', gap: '15px', justifyContent: 'center', flexWrap: 'wrap'}}>
            {trends.map((entry, index) => (
              <div key={index} style={{display: 'flex', alignItems: 'center', gap: '5px'}}>
                <div style={{width: '12px', height: '12px', background: COLORS[index % COLORS.length]}} />
                <span style={{color: '#1A5C0A', fontSize: '11px'}}>{entry.date}: {entry.new_campaigns} campaigns</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============== INVESTIGATE ==============

function InvestigateView({ token }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchTerm.trim()) {
      setError('Please enter a domain to investigate');
      return;
    }
    
    // Clean the domain input - remove protocol and path
    let cleanDomain = searchTerm.trim();
    
    // Remove protocol (http://, https://)
    cleanDomain = cleanDomain.replace(/^https?:\/\//, '');
    
    // Remove trailing slash and path
    cleanDomain = cleanDomain.split('/')[0];
    
    // Remove www. prefix for consistency
    cleanDomain = cleanDomain.replace(/^www\./, '');
    
    // Basic validation - must look like a domain
    if (!cleanDomain || cleanDomain.length < 3) {
      setError('Please enter a valid domain (e.g., example.com)');
      return;
    }
    
    console.log('🔍 Investigating domain:', cleanDomain);
    
    // Clear previous results and errors
    setError(null);
    setInvestigation(null);
    setLoading(true);
    
    try {
      // Send cleaned domain (no encoding needed for simple domain)
      const res = await fetch(`${API_BASE}/dashboard/investigate/${cleanDomain}`, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
      
      // Check response status
      if (!res.ok) {
        if (res.status === 401) {
          throw new Error('Authentication failed. Please login again.');
        }
        if (res.status === 404) {
          throw new Error('Investigation endpoint not found.');
        }
        if (res.status >= 500) {
          throw new Error('Server error. Please try again later.');
        }
        throw new Error(`HTTP error: ${res.status}`);
      }
      
      const data = await res.json();
      
      // Validate response data
      if (!data || typeof data !== 'object') {
        throw new Error('Invalid response from server');
      }
      
      console.log('✅ Investigation result:', data);
      setInvestigation(data);
    } catch (err) {
      console.error('❌ Investigation error:', err);
      setError(err.message || 'Failed to investigate domain. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Helper to get risk level color
  const getRiskColor = (score) => {
    if (score > 0.7) return '#FF3333';
    if (score > 0.4) return '#FFFF00';
    return '#00FF66';
  };

  return (
    <div className="page-content">
      {/* Error Display */}
      {error && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(255, 51, 51, 0.2)',
          border: '1px solid #FF3333',
          borderRadius: '4px',
          marginBottom: '20px',
          color: '#FF3333',
          fontSize: '14px'
        }}>
          ⚠️ {error}
        </div>
      )}
      
      <form className="investigate-form" onSubmit={handleSearch}>
        <input
          type="text"
          placeholder="Enter domain to investigate (e.g., paypal-verify.ml)..."
          value={searchTerm}
          onChange={(e) => {
            setSearchTerm(e.target.value);
            setError(null);
          }}
          className="input"
          style={{flex: 1}}
          disabled={loading}
        />
        <button type="submit" disabled={loading || !searchTerm.trim()} className="btn btn-primary">
          {loading ? '⏳ ANALYZING...' : '🔍 INVESTIGATE'}
        </button>
      </form>

      {/* Loading State */}
      {loading && (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          color: '#39FF14'
        }}>
          <div style={{fontSize: '24px', marginBottom: '10px'}}>⏳</div>
          <div>Analyzing domain...</div>
        </div>
      )}

      {/* Results Display */}
      {investigation && !loading && (
        <div className="investigate-grid">
          {/* Risk Score */}
          <div className="investigate-card">
            <h4>RISK ASSESSMENT</h4>
            <div className="risk-score" style={{
              color: getRiskColor(investigation.risk_score)
            }}>
              {(investigation.risk_score * 100).toFixed(0)}%
            </div>
            <div style={{
              marginTop: '8px',
              padding: '4px 8px',
              background: getRiskColor(investigation.risk_score) + '20',
              border: `1px solid ${getRiskColor(investigation.risk_score)}`,
              borderRadius: '4px',
              display: 'inline-block',
              fontSize: '12px',
              fontWeight: 'bold'
            }}>
              {investigation.risk_level || 'UNKNOWN'}
            </div>
            <div style={{marginTop: '12px', fontSize: '14px'}}>
              <div>Confidence: {((investigation.confidence || 0.75) * 100).toFixed(0)}%</div>
              <div style={{marginTop: '8px'}}>Detection: ML + Graph</div>
            </div>
          </div>

          {/* NLP Analysis */}
          <div className="investigate-card">
            <h4>NLP ANALYSIS</h4>
            <p style={{fontSize: '14px', lineHeight: '1.7'}}>
              {investigation.nlp_explanation || 'No analysis available'}
            </p>
          </div>

          {/* Detailed Analysis */}
          <div className="investigate-card">
            <h4>DETAILED ANALYSIS</h4>
            <div style={{display: 'grid', gap: '8px', fontSize: '13px'}}>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span style={{color: '#1A5C0A'}}>ML Score:</span>
                <span style={{color: getRiskColor(investigation.detailed_analysis?.ml_model_score)}}>
                  {((investigation.detailed_analysis?.ml_model_score || 0) * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span style={{color: '#1A5C0A'}}>Graph Score:</span>
                <span style={{color: getRiskColor(investigation.detailed_analysis?.graph_score)}}>
                  {((investigation.detailed_analysis?.graph_score || 0) * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between'}}>
                <span style={{color: '#1A5C0A'}}>Infrastructure:</span>
                <span style={{color: getRiskColor(investigation.detailed_analysis?.infrastructure_score)}}>
                  {((investigation.detailed_analysis?.infrastructure_score || 0) * 100).toFixed(0)}%
                </span>
              </div>
            </div>
          </div>

          {/* Security Checks */}
          <div className="investigate-card">
            <h4>SECURITY CHECKS</h4>
            <ul style={{listStyle: 'none', padding: 0, fontSize: '13px'}}>
              <li style={{padding: '6px 0', borderBottom: '1px solid #0D3D0D'}}>
                {investigation.security_checks?.ssl_valid ? '✅' : '❌'} SSL Certificate
              </li>
              <li style={{padding: '6px 0', borderBottom: '1px solid #0D3D0D'}}>
                {investigation.security_checks?.suspicious_tld ? '⚠️' : '✅'} Suspicious TLD
              </li>
              <li style={{padding: '6px 0', borderBottom: '1px solid #0D3D0D'}}>
                {investigation.security_checks?.known_malicious ? '❌' : '✅'} Known Malicious
              </li>
              <li style={{padding: '6px 0'}}>
                {investigation.security_checks?.campaign_linked ? '⚠️' : '✅'} Campaign Linked
              </li>
            </ul>
          </div>

          {/* DOM Indicators */}
          <div className="investigate-card">
            <h4>DOM INDICATORS</h4>
            <ul style={{listStyle: 'none', padding: 0}}>
              {(investigation.dom_indicators || []).map((ind, i) => (
                <li key={i} style={{padding: '8px 0', borderBottom: '1px solid #0D3D0D', fontSize: '13px'}}>
                  ▸ {ind}
                </li>
              ))}
              {(investigation.dom_indicators || []).length === 0 && (
                <li style={{padding: '8px 0', color: '#1A5C0A', fontSize: '13px'}}>
                  No specific indicators found
                </li>
              )}
            </ul>
          </div>

          {/* Domain Info */}
          <div className="investigate-card">
            <h4>DOMAIN INFO</h4>
            <div style={{display: 'grid', gap: '10px', fontSize: '14px'}}>
              <div><span style={{color: '#1A5C0A'}}>Age:</span> {investigation.security_checks?.domain_age_days || 'Unknown'} days</div>
              <div><span style={{color: '#1A5C0A'}}>Registrar:</span> {investigation.whois_summary?.registrar || 'Unknown'}</div>
              <div><span style={{color: '#1A5C0A'}}>Created:</span> {investigation.whois_summary?.created_date || 'Unknown'}</div>
            </div>
          </div>

          {/* Recommendations */}
          <div className="investigate-card wide">
            <h4>RECOMMENDATIONS</h4>
            <div style={{display: 'flex', gap: '12px', flexWrap: 'wrap'}}>
              {(investigation.recommendations || []).map((rec, i) => (
                <span key={i} style={{
                  padding: '8px 16px',
                  background: rec === 'Block' ? 'rgba(255, 51, 51, 0.2)' : rec === 'Warn' ? 'rgba(255, 255, 0, 0.2)' : 'rgba(0, 255, 102, 0.2)',
                  border: `1px solid ${rec === 'Block' ? '#FF3333' : rec === 'Warn' ? '#FFFF00' : '#00FF66'}`,
                  borderRadius: '4px',
                  color: rec === 'Block' ? '#FF3333' : rec === 'Warn' ? '#FFFF00' : '#00FF66',
                  fontWeight: 'bold',
                  fontSize: '13px'
                }}>
                  {rec}
                </span>
              ))}
            </div>
          </div>

          {/* Related Domains */}
          {(investigation.related_domains || []).length > 0 && (
            <div className="investigate-card wide">
              <h4>RELATED DOMAINS</h4>
              <table className="threats-table">
                <thead>
                  <tr>
                    <th>DOMAIN</th>
                    <th>RELATION</th>
                    <th>RISK</th>
                  </tr>
                </thead>
                <tbody>
                  {investigation.related_domains.map((rel, i) => (
                    <tr key={i}>
                      <td style={{fontFamily: 'var(--font-mono)'}}>{rel.domain}</td>
                      <td>{rel.relation}</td>
                      <td style={{color: getRiskColor(rel.risk)}}>{(rel.risk * 100).toFixed(0)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      
      {/* Empty State */}
      {!investigation && !loading && !error && (
        <div style={{
          textAlign: 'center',
          padding: '60px 20px',
          color: '#1A5C0A'
        }}>
          <div style={{fontSize: '48px', marginBottom: '20px'}}>🔍</div>
          <h3 style={{color: '#39FF14', marginBottom: '10px'}}>Domain Investigation</h3>
          <p>Enter a domain above to analyze potential phishing threats</p>
          <p style={{marginTop: '20px', fontSize: '13px'}}>
            Try: paypal-verify.ml, amazon-security.xyz, google-login.com
          </p>
        </div>
      )}
    </div>
  );
}

// ============== ADMIN ==============

function AdminView({ token }) {
  const [policyMode, setPolicyMode] = useState('BALANCED');
  const [overrides, setOverrides] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [policyRes, overridesRes] = await Promise.all([
          fetch(`${API_BASE}/admin/policy-mode`, { headers: { 'Authorization': `Bearer ${token}` } }),
          fetch(`${API_BASE}/admin/overrides`, { headers: { 'Authorization': `Bearer ${token}` } })
        ]);
        
        const policyData = await policyRes.json();
        const overridesData = await overridesRes.json();
        
        setPolicyMode(policyData.policy_mode || 'BALANCED');
        setOverrides(overridesData || []);
      } catch (err) {
        console.error('Failed to fetch admin data:', err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
  }, [token]);

  if (loading) return <div className="loading"></div>;

  return (
    <div className="page-content">
      <div className="admin-section">
        <h3>POLICY MODE</h3>
        
        <div className="policy-modes">
          <button 
            className={`policy-btn ${policyMode === 'STRICT' ? 'active' : ''}`}
            onClick={() => setPolicyMode('STRICT')}
          >
            <div className="policy-btn-icon">🔒</div>
            <div className="policy-btn-name">STRICT</div>
            <div className="policy-btn-desc">Block High + Medium</div>
          </button>
          
          <button 
            className={`policy-btn ${policyMode === 'BALANCED' ? 'active' : ''}`}
            onClick={() => setPolicyMode('BALANCED')}
          >
            <div className="policy-btn-icon">⚖</div>
            <div className="policy-btn-name">BALANCED</div>
            <div className="policy-btn-desc">Block High, Warn Medium</div>
          </button>
          
          <button 
            className={`policy-btn ${policyMode === 'PERMISSIVE' ? 'active' : ''}`}
            onClick={() => setPolicyMode('PERMISSIVE')}
          >
            <div className="policy-btn-icon">🔓</div>
            <div className="policy-btn-name">PERMISSIVE</div>
            <div className="policy-btn-desc">Block Known Only</div>
          </button>
        </div>
        
        <div style={{fontSize: '14px', color: '#1A5C0A', marginTop: '16px'}}>
          Current Policy: <strong style={{color: '#39FF14'}}>{policyMode}</strong>
        </div>
      </div>

      <div className="admin-section">
        <h3>ENTERPRISE OVERRIDES</h3>
        
        <div className="content-card">
          <table className="overrides-table">
            <thead>
              <tr>
                <th>DOMAIN</th>
                <th>ACTION</th>
                <th>REASON</th>
                <th>CREATED</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {overrides.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{textAlign: 'center', color: '#1A5C0A', padding: '40px !important'}}>
                    No overrides configured
                  </td>
                </tr>
              ) : (
                overrides.map(override => (
                  <tr key={override.id}>
                    <td style={{fontFamily: 'var(--font-mono)'}}>{override.domain}</td>
                    <td>
                      <span style={{
                        padding: '4px 10px',
                        border: `1px solid ${override.action === 'ALLOW' ? '#00FF66' : '#FF3333'}`,
                        color: override.action === 'ALLOW' ? '#00FF66' : '#FF3333',
                        fontSize: '11px'
                      }}>
                        {override.action}
                      </span>
                    </td>
                    <td>{override.reason || '—'}</td>
                    <td>{new Date(override.created_at).toLocaleDateString()}</td>
                    <td>
                      <button className="btn btn-danger" style={{padding: '6px 12px', fontSize: '8px'}}>
                        DELETE
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ============== MAIN APP ==============

function App() {
  const [activeView, setActiveView] = useState('overview');
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const login = async () => {
      try {
        const formData = new URLSearchParams();
        formData.append('username', 'admin');
        formData.append('password', 'admin123');
        
        const response = await fetch(`${API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData
        });
        
        if (response.ok) {
          const data = await response.json();
          setToken(data.access_token);
        }
      } catch (err) {
        console.error('Auto-login failed:', err);
      } finally {
        setLoading(false);
      }
    };
    
    login();
  }, []);

  if (loading) {
    return <div className="login-container"><div className="vignette"></div><div className="loading"></div></div>;
  }

  const renderView = () => {
    switch (activeView) {
      case 'overview': return <OverviewDashboard token={token} />;
      case 'live-threats': return <LiveThreats token={token} />;
      case 'campaigns': return <CampaignsView token={token} />;
      case 'graph': return <InfrastructureGraph token={token} />;
      case 'endpoints': return <EndpointsView token={token} />;
      case 'trends': return <TrendsView token={token} />;
      case 'investigate': return <InvestigateView token={token} />;
      case 'admin': return <AdminView token={token} />;
      default: return <OverviewDashboard token={token} />;
    }
  };

  const pageTitles = {
    overview: 'DASHBOARD OVERVIEW',
    'live-threats': 'LIVE THREAT MONITOR',
    campaigns: 'CAMPAIGN INTELLIGENCE',
    graph: 'INFRASTRUCTURE GRAPH',
    endpoints: 'ENDPOINT STATISTICS',
    trends: 'RISK TREND ANALYTICS',
    investigate: 'DOMAIN INVESTIGATION',
    admin: 'ENTERPRISE POLICY'
  };

  return (
    <div className="app-container">
      <div className="vignette"></div>
      <Header user={{name: 'Admin'}} onLogout={() => setToken(null)} />
      
      <div className="app-body">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />
        
        <main className="main-content">
          <div className="page-header">
            <h2>{pageTitles[activeView]}</h2>
            {activeView === 'live-threats' && (
              <div className="status-badge">
                <span className="status-dot"></span>
                LIVE
              </div>
            )}
          </div>
          
          {renderView()}
        </main>
      </div>
    </div>
  );
}

export default App;
